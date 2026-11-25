//! Transfer engine: scan, copy, verify, publish, link, delete - with the same
//! safety rules as the C++ implementation.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::win;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    Validate,
    Scan,
    Copy,
    Verify,
    Publish,
    Link,
    Cleanup,
    Done,
    Failed,
    Cancelled,
}

impl Phase {
    pub fn text(self) -> &'static str {
        match self {
            Phase::Validate => "Проверка условий",
            Phase::Scan => "Подготовка списка файлов",
            Phase::Copy => "Копирование",
            Phase::Verify => "Сверка копии",
            Phase::Publish => "Публикация копии",
            Phase::Link => "Создание ссылки",
            Phase::Cleanup => "Удаление старого экземпляра",
            Phase::Done => "Готово",
            Phase::Failed => "Ошибка",
            Phase::Cancelled => "Отменено",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Progress {
    pub phase: Phase,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub files_done: u64,
    pub files_total: u64,
    pub item: String,
}

impl Default for Phase {
    fn default() -> Self {
        Phase::Validate
    }
}

pub trait Sink {
    fn progress(&self, progress: &Progress);
    fn cancelled(&self) -> bool;
}

#[derive(Clone, Default)]
pub struct Faults {
    pub copy_failure: bool,
    pub verify_mismatch: bool,
    pub link_failure: bool,
    pub low_space: bool,
    pub force_flush_failure: bool,
    pub tamper_extra: bool,
    pub tamper_missing: bool,
}

#[derive(Clone, Default)]
pub struct Plan {
    pub valid: bool,
    pub error: String,
    pub source: String,
    pub source_parent: String,
    pub name: String,
    pub dest_parent: String,
    pub dest_final: String,
    pub staging: String,
    pub backup: String,
}

#[derive(Clone, Default)]
pub struct Outcome {
    pub ok: bool,
    pub cancelled: bool,
    pub needs_elevation: bool,
    pub message: String,
    pub detail: String,
    pub notes: String,
    pub leftover: String,
}

#[derive(Clone, Debug, Default)]
struct StreamInfo {
    name: String,
    size: u64,
    hash: String,
}

#[derive(Clone)]
struct ReparseLink {
    tag: u32,
    substitute: String,
    relative: bool,
    is_dir: bool,
    raw: Vec<u8>,
    link_text: String,
    inside_rel: String,
}

#[derive(Clone, Default)]
struct Entry {
    rel: String,
    is_dir: bool,
    attrs: u32,
    links: u32,
    size: u64,
    created: u64,
    modified: u64,
    serial: u64,
    index: u64,
    dacl: Option<String>,
    streams: Vec<StreamInfo>,
    hash: Option<String>,
    reparse: Option<ReparseLink>,
    hardlink_primary: Option<usize>,
}

#[derive(Clone, Default)]
struct Caps {
    fs: String,
    remote: bool,
    acl: bool,
    streams: bool,
    dir_streams: bool,
    hardlinks: bool,
    reparse: bool,
    tolerance_ms: u64,
    attr_mask: u32,
    check_created: bool,
}

const ATTR_MASK_FAT: u32 = win::FILE_ATTRIBUTE_HIDDEN | win::FILE_ATTRIBUTE_SYSTEM | win::FILE_ATTRIBUTE_READONLY
    | win::FILE_ATTRIBUTE_ARCHIVE;
const ATTR_MASK_NTFS: u32 = ATTR_MASK_FAT | 0x2000 | 0x100; // NOT_CONTENT_INDEXED | TEMPORARY

fn guid() -> String {
    // Simple unique value without extra dependencies.
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let counter = std::process::id() as u64;
    format!("{:x}-{:x}-{:x}", now.as_nanos(), counter, now.as_secs() ^ (counter << 16))
}

fn trim_input(value: &str) -> String {
    let mut text = value.trim().trim_matches('"').trim().to_string();
    // Keep the root form "C:\": trimming it would turn it into "C:", which opens the current directory.
    while text.len() > 3 && text.ends_with('\\') {
        text.pop();
    }
    text
}

fn same_path(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn under_or_equal(child: &str, parent: &str) -> bool {
    if parent.is_empty() || child.is_empty() {
        return false;
    }
    if same_path(child, parent) {
        return true;
    }
    let mut prefix = parent.to_string();
    if !prefix.ends_with('\\') {
        prefix.push('\\');
    }
    if child.len() <= prefix.len() {
        return false;
    }
    child[..prefix.len()].eq_ignore_ascii_case(&prefix)
}

fn critical_dirs() -> Vec<String> {
    let mut result = Vec::new();
    for name in ["SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData"] {
        if let Ok(value) = std::env::var(name) {
            if let Some(canonical) = win::canonical(&value) {
                result.push(canonical);
            }
        }
    }
    result
}

fn volume_fs(path: &str) -> String {
    win::volume_info(path).map(|v| v.fs).unwrap_or_default()
}

fn check_volume(path: &str) -> Result<(), String> {
    if win::volume_root(path).is_none() {
        return Err(format!("Не удалось определить том для пути: {}", path));
    }
    if win::volume_info(path).is_none() {
        return Err(format!("Не удалось прочитать сведения о томе для {}", path));
    }
    Ok(())
}

pub fn build_plan(source_input: &str, dest_input: &str) -> Plan {
    let mut plan = Plan::default();
    let source_text = trim_input(source_input);
    let dest_text = trim_input(dest_input);
    if source_text.is_empty() {
        plan.error = "Укажите папку, которую нужно перенести.".into();
        return plan;
    }
    if dest_text.is_empty() {
        plan.error = "Укажите папку назначения.".into();
        return plan;
    }
    let Some(source) = win::canonical(&source_text) else {
        plan.error = format!("Не удалось открыть исходную папку: {}", win::error_text(win::last_error()));
        return plan;
    };
    let Some(dest_parent) = win::canonical(&dest_text) else {
        plan.error = format!("Не удалось открыть папку назначения: {}", win::error_text(win::last_error()));
        return plan;
    };
    if source.len() <= 3 {
        plan.error = format!("Нельзя переносить корень диска: {}", source);
        return plan;
    }
    let Some(source_attrs) = win::attributes(&source) else {
        plan.error = format!("Исходная папка недоступна: {}", source);
        return plan;
    };
    if source_attrs & win::FILE_ATTRIBUTE_DIRECTORY == 0 {
        plan.error = format!("Исходный путь должен быть папкой: {}", source);
        return plan;
    }
    if source_attrs & win::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        plan.error = format!("Исходная папка уже является ссылкой: {}", source);
        return plan;
    }
    if !win::is_dir(&dest_parent) {
        plan.error = format!("Место назначения должно быть папкой: {}", dest_parent);
        return plan;
    }
    if win::is_reparse(&dest_parent) {
        plan.error = format!("Нельзя переносить в ссылку, выберите обычную папку: {}", dest_parent);
        return plan;
    }
    let name = win::leaf(&source);
    if name.is_empty() || name == "." || name == ".." {
        plan.error = "Не удалось определить имя переносимой папки.".into();
        return plan;
    }
    let dest_final = win::join(&dest_parent, &name);
    if !same_path(&win::parent(&dest_final), &dest_parent) {
        plan.error = format!("Некорректный путь назначения: {}", dest_final);
        return plan;
    }
    if win::path_exists(&dest_final) {
        plan.error = format!(
            "На новом месте уже есть объект с именем «{}»: {}\n\nНичего не перезаписывается. Укажите другую папку назначения.",
            name, dest_final
        );
        return plan;
    }
    if under_or_equal(&dest_parent, &source) {
        plan.error = "Папка назначения находится внутри переносимой папки.".into();
        return plan;
    }
    if under_or_equal(&source, &dest_final) {
        plan.error = "Исходная папка находится внутри папки назначения.".into();
        return plan;
    }
    if critical_dirs().iter().any(|dir| under_or_equal(&source, dir)) {
        plan.error = format!("Нельзя переносить системные каталоги Windows: {}", source);
        return plan;
    }
    if let Ok(profile) = std::env::var("USERPROFILE") {
        if let Some(canonical_profile) = win::canonical(&profile) {
            if same_path(&source, &canonical_profile) {
                plan.error = format!("Нельзя переносить папку профиля пользователя целиком: {}", source);
                return plan;
            }
        }
    }
    if let Err(error) = check_volume(&source).and_then(|_| check_volume(&dest_parent)) {
        plan.error = error;
        return plan;
    }
    let source_root = win::volume_root(&source).unwrap_or_default();
    let remote_source = win::volume_info(&source_root).map(|v| v.remote).unwrap_or(false);
    if !remote_source {
        let fs = volume_fs(&source);
        if !fs.eq_ignore_ascii_case("NTFS") && !fs.eq_ignore_ascii_case("ReFS") {
            plan.error = format!(
                "На этом томе нельзя создать ссылку: файловая система {}.\nНужен NTFS.",
                if fs.is_empty() { "неизвестна".to_string() } else { fs }
            );
            return plan;
        }
    }
    plan.valid = true;
    plan.source = source.clone();
    plan.source_parent = win::parent(&source);
    plan.name = name;
    plan.dest_parent = dest_parent.clone();
    plan.dest_final = dest_final.clone();
    plan.staging = win::join(&dest_parent, &format!(".linkerino-stage-{}", guid()));
    plan.backup = win::join(&plan.source_parent.clone(), &format!(".linkerino-backup-{}", guid()));
    plan
}

struct Ctx<'a> {
    sink: Option<&'a dyn Sink>,
    phase: Phase,
    bytes_done: u64,
    bytes_total: u64,
    files_done: u64,
    files_total: u64,
    item: String,
    last_report: Instant,
    cancelled: bool,
}

impl<'a> Ctx<'a> {
    fn new(sink: Option<&'a dyn Sink>) -> Self {
        Ctx {
            sink,
            phase: Phase::Validate,
            bytes_done: 0,
            bytes_total: 0,
            files_done: 0,
            files_total: 0,
            item: String::new(),
            last_report: Instant::now() - std::time::Duration::from_secs(1),
            cancelled: false,
        }
    }

    fn report(&mut self, force: bool) {
        if let Some(sink) = self.sink {
            if force || self.last_report.elapsed() >= std::time::Duration::from_millis(100) {
                self.last_report = Instant::now();
                sink.progress(&Progress {
                    phase: self.phase,
                    bytes_done: self.bytes_done,
                    bytes_total: self.bytes_total,
                    files_done: self.files_done,
                    files_total: self.files_total,
                    item: self.item.clone(),
                });
            }
        }
    }

    fn cancel_requested(&mut self) -> bool {
        if self.sink.map(|s| s.cancelled()).unwrap_or(false) {
            self.cancelled = true;
        }
        self.cancelled
    }
}

fn hash_stream(mut reader: impl Read, ctx: &mut Ctx) -> std::io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total += read as u64;
        ctx.bytes_done += read as u64;
        ctx.report(false);
        if ctx.cancel_requested() {
            return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "cancelled"));
        }
    }
    Ok((format!("{:x}", hasher.finalize()), total))
}

fn hash_file(path: &str, ctx: &mut Ctx) -> std::io::Result<String> {
    let file = File::open(path)?;
    hash_stream(file, ctx).map(|(hash, _)| hash)
}

fn stream_path(base: &str, name: &str) -> String {
    format!("{}:{}:$DATA", base, name)
}

fn copy_stream(source: &str, target: &str, ctx: &mut Ctx) -> std::io::Result<String> {
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new().write(true).create_new(true).open(target)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        output.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
        ctx.bytes_done += read as u64;
        ctx.report(false);
        if ctx.cancel_requested() {
            return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "cancelled"));
        }
    }
    output.sync_all()?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn scan_dir(root: &str, rel: &str, depth: u32, entries: &mut Vec<Entry>) -> Result<(), String> {
    if depth > 512 {
        return Err(format!("Слишком глубокая вложенность каталогов: {}", rel));
    }
    let plain = if rel.is_empty() { root.to_string() } else { win::join(root, rel) };
    let Some(info) = win::file_info(&plain, false) else {
        return Err(format!("Не удалось прочитать каталог {}", plain));
    };
    let mut dir = Entry {
        rel: rel.to_string(),
        is_dir: true,
        attrs: info.attrs,
        links: info.links,
        size: info.size,
        created: info.created,
        modified: info.modified,
        serial: info.serial,
        index: info.index,
        dacl: win::acl_signature(&plain),
        ..Default::default()
    };
    dir.streams = win::streams(&plain)
        .map_err(|code| format!("Не удалось перечислить потоки {}: {}", plain, win::error_text(code)))?
        .into_iter()
        .map(|s| StreamInfo { name: s.name, size: s.size, hash: String::new() })
        .collect();
    for stream in dir.streams.iter_mut() {
        let path = stream_path(&plain, &stream.name);
        let mut ctx = Ctx::new(None);
        stream.hash = hash_file(&path, &mut ctx).map_err(|e| format!("Ошибка чтения потока {}: {}", path, e))?;
    }
    entries.push(dir);
    let read_dir = match fs::read_dir(&plain) {
        Ok(value) => value,
        Err(error) => return Err(format!("Не удалось прочитать {}: {}", plain, error)),
    };
    for item in read_dir {
        let item = item.map_err(|e| format!("Ошибка чтения {}: {}", plain, e))?;
        let name = item.file_name().to_string_lossy().to_string();
        let child_rel = if rel.is_empty() { name.clone() } else { win::join(rel, &name) };
        let child_plain = win::join(&plain, &name);
        let Some(attrs) = win::attributes(&child_plain) else {
            return Err(format!("Не удалось прочитать атрибуты {}", child_plain));
        };
        if attrs & win::FILE_ATTRIBUTE_ENCRYPTED != 0 {
            return Err(format!("Зашифрованный файл EFS: {}", child_plain));
        }
        if attrs & win::FILE_ATTRIBUTE_OFFLINE != 0 {
            return Err(format!("Файл недоступен офлайн: {}", child_plain));
        }
        if attrs & win::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            let is_dir = attrs & win::FILE_ATTRIBUTE_DIRECTORY != 0;
            let reparse = win::read_reparse(&child_plain)
                .map_err(|code| format!("Не удалось прочитать ссылку {}: {}", child_plain, win::error_text(code)))?;
            let resolved = win::canonical(&child_plain).unwrap_or_default();
            let inside_rel = if !resolved.is_empty() && under_or_equal(&resolved, root) {
                resolved[root.len()..].trim_start_matches('\\').to_string()
            } else {
                String::new()
            };
            let link_text = if reparse.relative && !inside_rel.is_empty() {
                win::normalize_target(&reparse.substitute)
            } else if !resolved.is_empty() {
                resolved.clone()
            } else {
                win::normalize_target(&reparse.substitute)
            };
            entries.push(Entry {
                rel: child_rel,
                is_dir,
                attrs,
                created: 0,
                modified: 0,
                reparse: Some(ReparseLink {
                    tag: reparse.tag,
                    substitute: reparse.substitute,
                    relative: reparse.relative,
                    is_dir,
                    raw: reparse.raw,
                    link_text,
                    inside_rel,
                }),
                ..Default::default()
            });
            continue;
        }
        if attrs & win::FILE_ATTRIBUTE_DIRECTORY != 0 {
            scan_dir(root, &child_rel, depth + 1, entries)?;
            continue;
        }
        let Some(info) = win::file_info(&child_plain, false) else {
            return Err(format!("Не удалось прочитать файл {}", child_plain));
        };
        let mut file = Entry {
            rel: child_rel,
            is_dir: false,
            attrs: info.attrs,
            links: info.links,
            size: info.size,
            created: info.created,
            modified: info.modified,
            serial: info.serial,
            index: info.index,
            dacl: win::acl_signature(&child_plain),
            ..Default::default()
        };
        file.streams = win::streams(&child_plain)
            .map_err(|code| format!("Не удалось перечислить потоки {}: {}", child_plain, win::error_text(code)))?
            .into_iter()
            .map(|s| StreamInfo { name: s.name, size: s.size, hash: String::new() })
            .collect();
        for stream in file.streams.iter_mut() {
            let path = stream_path(&child_plain, &stream.name);
            let mut ctx = Ctx::new(None);
            stream.hash = hash_file(&path, &mut ctx).map_err(|e| format!("Ошибка чтения потока {}: {}", path, e))?;
        }
        if file.links > 1 {
            let mut ctx = Ctx::new(None);
            file.hash = Some(hash_file(&child_plain, &mut ctx).map_err(|e| format!("Ошибка чтения {}: {}", child_plain, e))?);
        }
        entries.push(file);
    }
    Ok(())
}

fn build_hardlink_groups(entries: &mut [Entry]) {
    use std::collections::HashMap;
    let mut first: HashMap<(u64, u64), usize> = HashMap::new();
    for index in 0..entries.len() {
        if entries[index].is_dir || entries[index].reparse.is_some() || entries[index].links <= 1 {
            continue;
        }
        let key = (entries[index].serial, entries[index].index);
        match first.get(&key) {
            None => {
                first.insert(key, index);
            }
            Some(&primary) => {
                let primary_hash = entries[primary].hash.clone();
                let this_hash = entries[index].hash.clone();
                if primary_hash.is_none() || this_hash.is_none() || primary_hash != this_hash {
                    continue;
                }
                entries[index].hardlink_primary = Some(primary);
            }
        }
    }
}

fn probe_caps(parent: &str) -> Result<Caps, String> {
    let info = win::volume_info(parent).ok_or_else(|| format!("Не удалось определить том: {}", parent))?;
    let fs_name = info.fs.clone();
    let is_ntfs = fs_name.eq_ignore_ascii_case("NTFS");
    let mut caps = Caps {
        fs: fs_name.clone(),
        remote: info.remote,
        attr_mask: if is_ntfs { ATTR_MASK_NTFS } else { ATTR_MASK_FAT },
        tolerance_ms: if is_ntfs { if info.remote { 2000 } else { 0 } } else { 2000 },
        check_created: is_ntfs,
        ..Default::default()
    };
    if is_ntfs && !info.remote {
        caps.acl = true;
        caps.streams = true;
        caps.dir_streams = true;
        caps.hardlinks = true;
        caps.reparse = true;
        return Ok(caps);
    }
    let probe_file = win::join(parent, &format!(".linkerino-probe-{}.tmp", guid()));
    if !win::write_whole(&probe_file, b"") {
        return Err(format!("Нет доступа на запись в {}: {}", parent, win::error_text(win::last_error())));
    }
    // Streams: write and read back.
    let stream = stream_path(&probe_file, "probe");
    if win::write_whole(&stream, b"probe") {
        if let Some(data) = win::read_whole(&stream) {
            caps.streams = data == b"probe";
        }
    }
    // Directory streams: create a temporary directory and write a stream into it.
    let probe_dir = win::join(parent, &format!(".linkerino-dirprobe-{}", guid()));
    if win::create_dir(&probe_dir) {
        let dir_stream = stream_path(&probe_dir, "probe");
        if win::write_whole(&dir_stream, b"dirprobe") {
            if let Some(data) = win::read_whole(&dir_stream) {
                caps.dir_streams = data == b"dirprobe";
            }
        }
        let _ = win::delete_dir(&probe_dir);
    }
    // ACL: set a protected NULL DACL, read it back, restore.
    if info.remote || fs_name.eq_ignore_ascii_case("ReFS") {
        caps.acl = probe_acl(&probe_file);
    }
    // Hard links.
    let link_probe = format!("{}.link", probe_file);
    caps.hardlinks = win::hard_link(&probe_file, &link_probe);
    if caps.hardlinks {
        let _ = win::delete_file(&link_probe);
    }
    // Creation time persistence.
    let stamp: u64 = 125911584000000000; // 2000-01-01 in FILETIME units
    if win::set_times(&probe_file, stamp, stamp, stamp) {
        if let Some(info) = win::file_info(&probe_file, false) {
            let difference = info.created.abs_diff(stamp);
            caps.check_created = difference <= 2000 * 10_000;
        }
    }
    let _ = win::delete_file(&probe_file);
    if info.remote {
        let link = win::join(parent, &format!(".linkerino-linkprobe-{}", guid()));
        caps.reparse = win::symlink(&link, parent, true).is_ok();
        if caps.reparse {
            let _ = win::delete_dir(&link);
        }
    }
    Ok(caps)
}

fn probe_acl(path: &str) -> bool {
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SetNamedSecurityInfoW};
    use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION};
    let mut name = win::api(path);
    let mut original: win::Pacl = std::ptr::null_mut();
    let mut descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let read = unsafe {
        GetNamedSecurityInfoW(name.as_ptr(), crate::win::SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                              std::ptr::null_mut(), std::ptr::null_mut(), &mut original, std::ptr::null_mut(),
                              &mut descriptor)
    };
    if read != 0 {
        return false;
    }
    let set_null = unsafe {
        SetNamedSecurityInfoW(name.as_mut_ptr(), crate::win::SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                              std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())
    };
    if set_null != 0 {
        unsafe { windows_sys::Win32::Foundation::LocalFree(descriptor as *mut _) };
        return false;
    }
    let applied = win::acl_signature(path).map(|s| s == "<null>").unwrap_or(false) && win::dacl_protected(path);
    // Put the original DACL back: the probe file is temporary, but it must not keep a NULL DACL.
    unsafe {
        SetNamedSecurityInfoW(name.as_mut_ptr(), crate::win::SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                              std::ptr::null_mut(), std::ptr::null_mut(), original, std::ptr::null_mut());
        windows_sys::Win32::Foundation::LocalFree(descriptor as *mut _);
    }
    applied
}

fn attribute_mask_match(actual: u32, expected: u32, mask: u32) -> bool {
    (actual & mask) == (expected & mask)
}

fn times_match(actual: u64, expected: u64, tolerance_ms: u64) -> bool {
    actual.abs_diff(expected) <= tolerance_ms * 10_000
}

fn copy_file(source: &str, target: &str, entry: &mut Entry, ctx: &mut Ctx, caps: &Caps) -> Result<(), String> {
    let file = File::open(source).map_err(|e| format!("Не удалось открыть {}: {}", source, e))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)
        .map_err(|e| format!("Не удалось создать {}: {}", target, e))?;
    let mut hasher = Sha256::new();
    let mut reader = std::io::BufReader::new(file);
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let read = reader.read(&mut buffer).map_err(|e| format!("Ошибка чтения {}: {}", source, e))?;
        if read == 0 {
            break;
        }
        output.write_all(&buffer[..read]).map_err(|e| format!("Ошибка записи {}: {}", target, e))?;
        hasher.update(&buffer[..read]);
        ctx.bytes_done += read as u64;
        ctx.report(false);
        if ctx.cancel_requested() {
            return Err("Отменено пользователем".into());
        }
    }
    output.sync_all().map_err(|e| format!("Не удалось сбросить данные {}: {}", target, e))?;
    drop(output);
    entry.hash = Some(format!("{:x}", hasher.finalize()));
    if caps.streams {
        for stream in entry.streams.iter_mut() {
            let source_stream = stream_path(source, &stream.name);
            let target_stream = stream_path(target, &stream.name);
            stream.hash = copy_stream(&source_stream, &target_stream, ctx)
                .map_err(|e| format!("Ошибка копирования потока {}: {}", source_stream, e))?;
        }
    }
    if caps.acl && !win::apply_acl(source, target) {
        return Err(format!("Не удалось сохранить права доступа для {}", target));
    }
    if !win::set_times(target, entry.created, entry.modified, entry.modified) {
        return Err(format!("Не удалось сохранить даты {}", target));
    }
    let attrs = entry.attrs & caps.attr_mask;
    if !win::set_attributes(target, attrs) {
        return Err(format!("Не удалось сохранить атрибуты {}", target));
    }
    Ok(())
}

fn copy_reparse(target: &str, link: &ReparseLink) -> Result<(), String> {
    if link.tag == 0xA000000C {
        win::symlink(target, &link.link_text, link.is_dir)
            .map_err(|code| format!("Не удалось создать ссылку {}: {}", target, win::error_text(code)))?;
        return Ok(());
    }
    if link.tag == 0xA0000003 {
        if !win::create_dir(target) {
            return Err(format!("Не удалось создать каталог для junction {}", target));
        }
        if !win::write_junction(target, &link.raw) {
            return Err(format!("Не удалось создать junction {}", target));
        }
        return Ok(());
    }
    Err(format!("Неподдерживаемый тип ссылки: {}", target))
}

fn copy_tree(plan: &Plan, entries: &mut [Entry], ctx: &mut Ctx, faults: &Faults, caps: &Caps) -> Result<(), String> {
    for index in 0..entries.len() {
        if !entries[index].is_dir || entries[index].reparse.is_some() {
            continue;
        }
        let rel = entries[index].rel.clone();
        let target = if rel.is_empty() { plan.staging.clone() } else { win::join(&plan.staging, &rel) };
        if !win::create_dir(&target) {
            return Err(format!("Не удалось создать каталог {}", target));
        }
        if caps.acl {
            let source = if rel.is_empty() { plan.source.clone() } else { win::join(&plan.source, &rel) };
            if !win::apply_acl(&source, &target) {
                return Err(format!("Не удалось сохранить права доступа для {}", target));
            }
        }
        if caps.dir_streams && !entries[index].streams.is_empty() {
            let source = if rel.is_empty() { plan.source.clone() } else { win::join(&plan.source, &rel) };
            for stream_index in 0..entries[index].streams.len() {
                let name = entries[index].streams[stream_index].name.clone();
                let source_stream = stream_path(&source, &name);
                let target_stream = stream_path(&target, &name);
                let hash = copy_stream(&source_stream, &target_stream, ctx)
                    .map_err(|e| format!("Ошибка копирования потока {}: {}", source_stream, e))?;
                entries[index].streams[stream_index].hash = hash;
            }
        }
    }
    for index in 0..entries.len() {
        let Some(link) = entries[index].reparse.clone() else { continue };
        let target = win::join(&plan.staging, &entries[index].rel);
        ctx.item = entries[index].rel.clone();
        ctx.report(true);
        copy_reparse(&target, &link)?;
    }
    for index in 0..entries.len() {
        if entries[index].is_dir || entries[index].reparse.is_some() {
            continue;
        }
        if faults.copy_failure {
            return Err("Тестовый сбой копирования".into());
        }
        let rel = entries[index].rel.clone();
        let source = win::join(&plan.source, &rel);
        let target = win::join(&plan.staging, &rel);
        ctx.item = rel.clone();
        ctx.report(true);
        let mut handled = false;
        if let Some(primary) = entries[index].hardlink_primary {
            if caps.hardlinks {
                let primary_rel = entries[primary].rel.clone();
                let primary_path = win::join(&plan.staging, &primary_rel);
                if !win::hard_link(&primary_path, &target) {
                    return Err(format!("Не удалось создать жёсткую ссылку {}", target));
                }
                entries[index].hash = entries[primary].hash.clone();
                handled = true;
            }
        }
        if !handled {
            let mut copy = entries[index].clone();
            copy_file(&source, &target, &mut copy, ctx, caps)?;
            entries[index].hash = copy.hash.clone();
            entries[index].streams = copy.streams.clone();
        }
        ctx.files_done += 1;
        ctx.report(true);
    }
    for index in (0..entries.len()).rev() {
        let entry = &entries[index];
        if !entry.is_dir || entry.reparse.is_some() {
            continue;
        }
        let target = if entry.rel.is_empty() { plan.staging.clone() } else { win::join(&plan.staging, &entry.rel) };
        if !win::set_times(&target, entry.created, entry.modified, entry.modified) {
            return Err(format!("Не удалось сохранить даты {}", target));
        }
        let mut attrs = entry.attrs & caps.attr_mask;
        attrs &= !win::FILE_ATTRIBUTE_READONLY;
        if !win::set_attributes(&target, attrs) {
            return Err(format!("Не удалось сохранить атрибуты {}", target));
        }
    }
    Ok(())
}
fn verify_reparse(root: &str, entry: &Entry, caps: &Caps) -> Result<(), String> {
    let plain = win::join(root, &entry.rel);
    let Some(attrs) = win::attributes(&plain) else {
        return Err(format!("Ссылка не создана: {}", plain));
    };
    if attrs & win::FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        return Err(format!("В копии нет ссылки: {}", plain));
    }
    let link = entry.reparse.clone().unwrap();
    let actual = win::read_reparse(&plain)
        .map_err(|code| format!("Не удалось прочитать ссылку {}: {}", plain, win::error_text(code)))?;
    if actual.tag != link.tag {
        return Err(format!("Тип ссылки не совпадает: {}", plain));
    }
    let expected = if link.tag == 0xA0000003 {
        win::normalize_target(&link.substitute)
    } else if link.link_text.is_empty() {
        win::normalize_target(&link.substitute)
    } else {
        link.link_text.clone()
    };
    if !win::normalize_target(&actual.substitute).eq_ignore_ascii_case(&expected) {
        return Err(format!("Цель ссылки не совпадает: {} -> {}", plain, actual.substitute));
    }
    if link.relative && !link.inside_rel.is_empty() {
        let resolved = win::canonical(&plain).ok_or_else(|| format!("Относительная ссылка не открывается: {}", plain))?;
        let expected_path = win::join(root, &link.inside_rel);
        if !win::normalize_target(&resolved).eq_ignore_ascii_case(&expected_path) {
            return Err(format!("Относительная ссылка ведёт не туда: {}", plain));
        }
    }
    let _ = caps;
    Ok(())
}

fn verify_entry(root: &str, entry: &Entry, ctx: &mut Ctx, caps: &Caps) -> Result<(), String> {
    let plain = if entry.rel.is_empty() { root.to_string() } else { win::join(root, &entry.rel) };
    if entry.reparse.is_some() {
        return verify_reparse(root, entry, caps);
    }
    let Some(info) = win::file_info(&plain, false) else {
        return Err(format!("Не удалось прочитать {}", plain));
    };
    if (info.attrs & win::FILE_ATTRIBUTE_DIRECTORY != 0) != entry.is_dir {
        return Err(format!("Тип объекта не совпадает: {}", plain));
    }
    if caps.acl {
        let signature = win::acl_signature(&plain).ok_or_else(|| format!("Не удалось прочитать права доступа: {}", plain))?;
        if Some(&signature) != entry.dacl.as_ref() {
            return Err(format!("Права доступа не совпадают: {}", plain));
        }
        if !win::dacl_protected(&plain) {
            return Err(format!("Права доступа к копии не защищены от наследования: {}", plain));
        }
    }
    if !entry.is_dir {
        if !attribute_mask_match(info.attrs, entry.attrs, caps.attr_mask) {
            return Err(format!("Атрибуты файла не совпадают: {}", plain));
        }
        if info.size != entry.size {
            return Err(format!("Размер файла не совпадает: {}", plain));
        }
        if !times_match(info.modified, entry.modified, caps.tolerance_ms)
            || (caps.check_created && !times_match(info.created, entry.created, caps.tolerance_ms))
        {
            return Err(format!("Даты файла не совпадают: {}", plain));
        }
        let hash = hash_file(&plain, ctx).map_err(|e| format!("Ошибка сверки {}: {}", plain, e))?;
        if Some(&hash) != entry.hash.as_ref() {
            return Err(format!("Содержимое файла не совпадает: {}", plain));
        }
        if caps.streams {
            let actual = win::streams(&plain)
                .map_err(|code| format!("Не удалось перечислить потоки {}: {}", plain, win::error_text(code)))?;
            if actual.len() != entry.streams.len() {
                return Err(format!("Набор потоков файла не совпадает: {}", plain));
            }
            for (index, stream) in entry.streams.iter().enumerate() {
                if actual[index].name != stream.name {
                    return Err(format!("Имя потока не совпадает: {}", plain));
                }
                let path = stream_path(&plain, &stream.name);
                let hash = hash_file(&path, ctx).map_err(|e| format!("Ошибка сверки потока {}: {}", path, e))?;
                if hash != stream.hash {
                    return Err(format!("Содержимое потока не совпадает: {}", path));
                }
            }
        }
    } else {
        if caps.dir_streams {
            let actual = win::streams(&plain)
                .map_err(|code| format!("Не удалось перечислить потоки {}: {}", plain, win::error_text(code)))?;
            if actual.len() != entry.streams.len() {
                return Err(format!("Набор потоков каталога не совпадает: {}", plain));
            }
            for stream in entry.streams.iter() {
                let path = stream_path(&plain, &stream.name);
                let hash = hash_file(&path, ctx).map_err(|e| format!("Ошибка сверки потока {}: {}", path, e))?;
                if hash != stream.hash {
                    return Err(format!("Содержимое потока каталога не совпадает: {}", path));
                }
            }
        }
        if !times_match(info.modified, entry.modified, caps.tolerance_ms)
            || (caps.check_created && !times_match(info.created, entry.created, caps.tolerance_ms))
        {
            return Err(format!("Даты каталога не совпадают: {}", plain));
        }
    }
    ctx.item = entry.rel.clone();
    Ok(())
}

fn collect_paths(root: &str) -> Result<Vec<String>, String> {
    fn walk(root: &str, rel: &str, out: &mut Vec<String>) -> Result<(), String> {
        out.push(rel.to_string());
        let plain = if rel.is_empty() { root.to_string() } else { win::join(root, rel) };
        let read = fs::read_dir(&plain).map_err(|e| format!("Не удалось прочитать {}: {}", plain, e))?;
        for item in read {
            let item = item.map_err(|e| format!("Ошибка чтения {}: {}", plain, e))?;
            let name = item.file_name().to_string_lossy().to_string();
            let child_rel = if rel.is_empty() { name.clone() } else { win::join(rel, &name) };
            let child_plain = win::join(&plain, &name);
            let attrs = win::attributes(&child_plain)
                .ok_or_else(|| format!("Не удалось прочитать атрибуты {}", child_plain))?;
            out.push(child_rel.clone());
            if attrs & win::FILE_ATTRIBUTE_DIRECTORY != 0 && attrs & win::FILE_ATTRIBUTE_REPARSE_POINT == 0 {
                walk(root, &child_rel, out)?;
            }
        }
        Ok(())
    }
    let mut result = Vec::new();
    walk(root, "", &mut result)?;
    Ok(result)
}

fn describe_path(path: &str) -> String {
    if path.is_empty() {
        "<корень>".to_string()
    } else {
        path.to_string()
    }
}

/// Compares the actual set of paths with the scanned one: missing and extra objects are both failures.
fn verify_path_set(root: &str, entries: &[Entry]) -> Result<(), String> {
    let mut expected: Vec<String> = entries.iter().map(|entry| entry.rel.clone()).collect();
    let mut actual = collect_paths(root)?;
    expected.sort();
    actual.sort();
    expected.dedup();
    actual.dedup();
    if expected == actual {
        return Ok(());
    }
    if let Some(missing) = expected.iter().find(|path| !actual.contains(path)) {
        return Err(format!("В копии нет объекта: {}", describe_path(missing)));
    }
    if let Some(extra) = actual.iter().find(|path| !expected.contains(path)) {
        return Err(format!("В копии лишний объект: {}", describe_path(extra)));
    }
    Err("Набор путей в копии не совпадает".to_string())
}

fn verify_tree(root: &str, entries: &[Entry], ctx: &mut Ctx, caps: &Caps) -> Result<(), String> {
    // The set check runs first: a missing or extra object also changes folder timestamps,
    // and that report would hide the real reason.
    verify_path_set(root, entries)?;
    for entry in entries {
        ctx.item = entry.rel.clone();
        ctx.report(false);
        verify_entry(root, entry, ctx, caps)?;
        if ctx.cancel_requested() {
            return Err("Отменено пользователем".into());
        }
    }
    if !caps.hardlinks {
        return Ok(());
    }
    use std::collections::HashMap;
    let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for (index, entry) in entries.iter().enumerate() {
        if let Some(primary) = entry.hardlink_primary {
            groups.entry(primary).or_default().push(index);
        }
    }
    for (primary, members) in groups {
        let mut names = vec![entries[primary].rel.clone()];
        for member in members {
            names.push(entries[member].rel.clone());
        }
        let first = win::file_info(&win::join(root, &names[0]), false)
            .ok_or_else(|| format!("Не удалось прочитать {}", names[0]))?;
        if first.links as usize != names.len() {
            return Err(format!("Число жёстких ссылок не совпадает: {}", names[0]));
        }
        for name in names.iter().skip(1) {
            let other = win::file_info(&win::join(root, name), false)
                .ok_or_else(|| format!("Не удалось прочитать {}", name))?;
            if other.index != first.index || other.serial != first.serial {
                return Err(format!("Жёсткая ссылка не воссоздана: {}", name));
            }
        }
    }
    Ok(())
}

fn verify_source_unchanged(plan: &Plan, entries: &[Entry]) -> Result<(), String> {
    for entry in entries {
        let plain = if entry.rel.is_empty() { plan.source.clone() } else { win::join(&plan.source, &entry.rel) };
        if let Some(link) = &entry.reparse {
            let actual = win::read_reparse(&plain)
                .map_err(|code| format!("Не удалось прочитать ссылку {}: {}", plain, win::error_text(code)))?;
            if actual.tag != link.tag
                || !win::normalize_target(&actual.substitute)
                    .eq_ignore_ascii_case(&win::normalize_target(&link.substitute))
            {
                return Err(format!("Исходная ссылка изменилась во время переноса: {}", plain));
            }
            continue;
        }
        let info = win::file_info(&plain, false).ok_or_else(|| format!("Не удалось прочитать {}", plain))?;
        // A directory's size is the size of its index, not data: only files are compared by size.
        if (info.attrs & win::FILE_ATTRIBUTE_DIRECTORY != 0) != entry.is_dir
            || (!entry.is_dir && info.size != entry.size)
            || info.serial != entry.serial
            || info.index != entry.index
            || info.links != entry.links
            || info.modified != entry.modified
        {
            return Err(format!("Исходный объект изменился во время переноса: {}", plain));
        }
        if !entry.is_dir {
            let mut ctx = Ctx::new(None);
            let hash = hash_file(&plain, &mut ctx).map_err(|e| format!("Ошибка сверки {}: {}", plain, e))?;
            if Some(&hash) != entry.hash.as_ref() {
                return Err(format!("Содержимое исходного файла изменилось: {}", plain));
            }
        }
    }
    Ok(())
}

fn journal_dir() -> Option<std::path::PathBuf> {
    if let Ok(custom) = std::env::var("LINKERINO_JOURNAL_DIR") {
        if !custom.trim().is_empty() {
            let path = Path::new(custom.trim()).to_path_buf();
            let _ = fs::create_dir_all(&path);
            return Some(path);
        }
    }
    let base = std::env::var("LOCALAPPDATA").ok().map(|v| format!("{}\\Linkerino", v))?;
    let _ = fs::create_dir_all(&base);
    Some(Path::new(&base).to_path_buf())
}

fn journal_path(id: &str) -> Option<std::path::PathBuf> {
    Some(journal_dir()?.join(format!("journal-{}.txt", id)))
}

fn write_journal(id: &str, plan: &Plan, state: &str, extra: &str) {
    let Some(path) = journal_path(id) else { return };
    let content = format!(
        "state={}\nsource={}\ndest={}\nstaging={}\nbackup={}\n{}\n",
        state, plan.source, plan.dest_final, plan.staging, plan.backup, extra
    );
    let _ = fs::write(path, content);
}

fn remove_journal(id: &str) {
    if let Some(path) = journal_path(id) {
        let _ = fs::remove_file(path);
    }
}

fn remove_tree(path: &str) -> bool {
    let Some(attrs) = win::attributes(path) else { return true };
    if attrs & win::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return win::delete_dir(path) || win::delete_file(path);
    }
    if attrs & win::FILE_ATTRIBUTE_DIRECTORY != 0 {
        if let Ok(read_dir) = fs::read_dir(path) {
            for item in read_dir.flatten() {
                let child = item.path().to_string_lossy().to_string();
                if !remove_tree(&child) {
                    return false;
                }
            }
        }
        return win::delete_dir(path);
    }
    if attrs & win::FILE_ATTRIBUTE_READONLY != 0 {
        let _ = win::set_attributes(path, attrs & !win::FILE_ATTRIBUTE_READONLY);
    }
    win::delete_file(path)
}

fn delete_backup(plan: &Plan, entries: &[Entry], dest_serial: u64, dest_index: u64) -> Result<(), (String, String)> {
    let mut processed = 0usize;
    for entry in entries.iter().rev() {
        if processed % 32 == 0 {
            if !link_still_valid(&plan.source, &plan.dest_final, dest_serial, dest_index) {
                return Err((format!("Ссылка на новое место перестала быть доступной: {}", plan.source), plan.backup.clone()));
            }
        }
        processed += 1;
        let plain = if entry.rel.is_empty() { plan.backup.clone() } else { win::join(&plan.backup, &entry.rel) };
        let Some(attrs) = win::attributes(&plain) else {
            return Err((format!("Объект резерва исчез: {}", plain), plain));
        };
        if attrs & win::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            let Some(link) = &entry.reparse else {
                return Err((format!("В резерве появилась ссылка: {}", plain), plain));
            };
            let actual = win::read_reparse(&plain)
                .map_err(|code| (format!("Не удалось прочитать ссылку в резерве {}: {}", plain, win::error_text(code)), plain.clone()))?;
            if actual.tag != link.tag
                || !win::normalize_target(&actual.substitute)
                    .eq_ignore_ascii_case(&win::normalize_target(&link.substitute))
            {
                return Err((format!("Ссылка в резерве изменилась: {}", plain), plain));
            }
            if link.is_dir {
                if !win::delete_dir(&plain) {
                    return Err((format!("Не удалось удалить ссылку {}", plain), plain));
                }
            } else if !win::delete_file(&plain) {
                return Err((format!("Не удалось удалить ссылку {}", plain), plain));
            }
            continue;
        }
        if entry.is_dir {
            for stream in &entry.streams {
                let path = stream_path(&plain, &stream.name);
                let mut ctx = Ctx::new(None);
                let hash = hash_file(&path, &mut ctx).map_err(|e| (format!("Ошибка сверки потока {}: {}", path, e), plain.clone()))?;
                if hash != stream.hash {
                    return Err((format!("Содержимое потока каталога в резерве изменилось: {}", plain), plain));
                }
            }
            if !win::delete_dir(&plain) {
                return Err((format!("Не удалось удалить каталог резерва {}", plain), plain));
            }
            continue;
        }
        let info = win::file_info(&plain, false).ok_or_else(|| (format!("Не удалось прочитать {}", plain), plain.clone()))?;
        if info.index != entry.index || info.serial != entry.serial || info.size != entry.size || info.modified != entry.modified {
            return Err((format!("Файл резерва изменился: {}", plain), plain));
        }
        let mut ctx = Ctx::new(None);
        let hash = hash_file(&plain, &mut ctx).map_err(|e| (format!("Ошибка сверки {}: {}", plain, e), plain.clone()))?;
        if Some(&hash) != entry.hash.as_ref() {
            return Err((format!("Содержимое файла резерва изменилось: {}", plain), plain));
        }
        for stream in &entry.streams {
            let path = stream_path(&plain, &stream.name);
            let mut ctx = Ctx::new(None);
            let hash = hash_file(&path, &mut ctx).map_err(|e| (format!("Ошибка сверки потока {}: {}", path, e), plain.clone()))?;
            if hash != stream.hash {
                return Err((format!("Содержимое потока резерва изменилось: {}", plain), plain));
            }
        }
        if attrs & win::FILE_ATTRIBUTE_READONLY != 0 {
            let _ = win::set_attributes(&plain, attrs & !win::FILE_ATTRIBUTE_READONLY);
        }
        if !win::delete_file(&plain) {
            return Err((format!("Не удалось удалить файл резерва {}", plain), plain));
        }
    }
    Ok(())
}

fn link_still_valid(link: &str, target: &str, serial: u64, index: u64) -> bool {
    let Some(attrs) = win::attributes(link) else { return false };
    if attrs & win::FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        return false;
    }
    let Ok(reparse) = win::read_reparse(link) else { return false };
    if reparse.tag != 0xA000000C {
        return false;
    }
    let stored = win::normalize_target(&reparse.substitute);
    if !stored.eq_ignore_ascii_case(&win::normalize_target(target)) {
        return false;
    }
    let Some(info) = win::file_info(link, false) else { return false };
    info.serial == serial && info.index == index
}

pub fn execute(plan: &Plan, sink: Option<&dyn Sink>, faults: &Faults) -> Outcome {
    let mut outcome = Outcome::default();
    if !plan.valid {
        outcome.message = "Проверка путей не пройдена.".into();
        outcome.detail = plan.error.clone();
        return outcome;
    }
    let mut ctx = Ctx::new(sink);
    let journal_id = guid();
    write_journal(&journal_id, plan, "start", "");

    let fail = |outcome: &mut Outcome, message: String, detail: String, state: &str| {
        outcome.ok = false;
        outcome.message = message;
        outcome.detail = detail.clone();
        write_journal(&journal_id, plan, state, &format!("error={}", detail));
    };

    // Preflight: can we create a directory symlink next to the source?
    ctx.phase = Phase::Validate;
    ctx.item = "Проверка прав на ссылку".into();
    ctx.report(true);
    let probe_link = win::join(&plan.source_parent, &format!(".linkerino-probe-{}", guid()));
    if let Err(code) = win::symlink(&probe_link, &plan.dest_final, true) {
        fail(&mut outcome, "Не удалось проверить возможность создать ссылку. Перенос не начат, данные не тронуты.".into(),
             win::error_text(code), "failed");
        outcome.needs_elevation = code == 1314;
        return outcome;
    }
    let _ = win::delete_dir(&probe_link);
    if win::path_exists(&plan.staging) {
        fail(&mut outcome, "Служебная папка уже существует. Перенос не начат.".into(), plan.staging.clone(), "failed");
        return outcome;
    }
    if !win::create_dir(&plan.staging) {
        fail(&mut outcome, "Не удалось создать временную папку. Данные не тронуты.".into(),
             win::error_text(win::last_error()), "failed");
        return outcome;
    }
    write_journal(&journal_id, plan, "copying", "");

    let cleanup_staging = |outcome: &mut Outcome| {
        if !remove_tree(&plan.staging) {
            outcome.leftover = plan.staging.clone();
        }
    };

    // Scan.
    ctx.phase = Phase::Scan;
    ctx.item = plan.source.clone();
    ctx.report(true);
    let mut entries: Vec<Entry> = Vec::new();
    if let Err(error) = scan_dir(&plan.source, "", 0, &mut entries) {
        cleanup_staging(&mut outcome);
        fail(&mut outcome, "Перенос остановлен до копирования: неподдерживаемые объекты. Оригинал не изменён.".into(),
             error, "failed");
        return outcome;
    }
    build_hardlink_groups(&mut entries);
    let caps = match probe_caps(&plan.dest_parent) {
        Ok(value) => value,
        Err(error) => {
            cleanup_staging(&mut outcome);
            fail(&mut outcome, "Новое место недоступно для записи. Оригинал не изменён.".into(), error, "failed");
            return outcome;
        }
    };
    let has_links = entries.iter().any(|e| e.reparse.is_some());
    if has_links && !caps.reparse {
        cleanup_staging(&mut outcome);
        fail(&mut outcome, "В папке есть ссылки, а на новом месте их создать нельзя. Оригинал не изменён.".into(),
             format!("Файловая система назначения ({}) не поддерживает ссылки. Выберите диск NTFS.", caps.fs), "failed");
        return outcome;
    }
    let mut notes = String::new();
    if !caps.acl {
        notes.push_str("Права доступа NTFS не перенесены: файловая система назначения их не поддерживает.\n");
    }
    if !caps.streams {
        let count: usize = entries.iter().map(|e| e.streams.len()).sum();
        if count > 0 {
            notes.push_str(&format!("Именованные потоки NTFS не перенесены: {}.\n", count));
        }
    }
    if !caps.hardlinks {
        let groups = entries.iter().filter(|e| e.hardlink_primary.is_some()).count();
        if groups > 0 {
            notes.push_str(&format!("Жёсткие ссылки не сохранены: {} файл(ов) скопированы отдельно.\n", groups));
        }
    }
    outcome.notes = notes;

    let mut total_bytes = 0u64;
    let mut total_files = 0u64;
    for entry in &entries {
        if entry.reparse.is_some() {
            continue;
        }
        if entry.is_dir {
            if caps.dir_streams {
                total_bytes += entry.streams.iter().map(|s| s.size).sum::<u64>();
            }
            continue;
        }
        if entry.hardlink_primary.is_some() && caps.hardlinks {
            continue;
        }
        total_bytes += entry.size + entry.streams.iter().map(|s| s.size).sum::<u64>();
        total_files += 1;
    }
    ctx.bytes_total = total_bytes;
    ctx.files_total = total_files;
    let free = if faults.low_space { Some(0) } else { win::free_space(&plan.dest_parent) };
    if let Some(free) = free {
        if total_bytes > free {
            cleanup_staging(&mut outcome);
            fail(&mut outcome, "На новом диске недостаточно свободного места. Оригинал не изменён.".into(),
                 format!("Нужно {} байт, свободно {}", total_bytes, free), "failed");
            return outcome;
        }
    }

    // Copy.
    ctx.phase = Phase::Copy;
    ctx.item.clear();
    ctx.report(true);
    if let Err(error) = copy_tree(plan, &mut entries, &mut ctx, faults, &caps) {
        cleanup_staging(&mut outcome);
        if ctx.cancelled {
            outcome.cancelled = true;
            outcome.message = "Отменено до изменения исходной папки. Оригинал на месте.".into();
            outcome.detail = error.clone();
            write_journal(&journal_id, plan, "cancelled", &format!("error={}", error));
            return outcome;
        }
        fail(&mut outcome, "Копирование не завершено. Оригинал не изменён.".into(), error, "failed");
        return outcome;
    }

    // Test-only tampering with the published staging copy: the path-set check must reject it.
    if faults.tamper_extra {
        let extra = win::join(&plan.staging, "linkerino-tamper-extra.tmp");
        let _ = win::write_whole(&extra, b"tamper");
    }
    if faults.tamper_missing {
        if let Some(entry) = entries.iter().find(|e| !e.is_dir && e.reparse.is_none()) {
            let path = win::join(&plan.staging, &entry.rel);
            let _ = win::delete_file(&path);
        }
    }

    // Verify.
    ctx.phase = Phase::Verify;
    ctx.bytes_done = 0;
    ctx.report(true);
    if let Err(error) = verify_tree(&plan.staging, &entries, &mut ctx, &caps) {
        if ctx.cancelled {
            cleanup_staging(&mut outcome);
            outcome.cancelled = true;
            outcome.message = "Отменено во время сверки. Оригинал на месте.".into();
            write_journal(&journal_id, plan, "cancelled", &format!("error={}", error));
            return outcome;
        }
        cleanup_staging(&mut outcome);
        fail(&mut outcome, "Сверка копии не прошла. Оригинал не изменён.".into(), error, "failed");
        return outcome;
    }
    if faults.verify_mismatch {
        cleanup_staging(&mut outcome);
        fail(&mut outcome, "Сверка копии не прошла. Оригинал не изменён.".into(), "Тестовый сбой сверки".into(), "failed");
        return outcome;
    }
    if let Err(error) = verify_source_unchanged(plan, &entries) {
        cleanup_staging(&mut outcome);
        fail(&mut outcome, "Исходная папка изменилась во время переноса. Оригинал не тронут.".into(), error, "failed");
        return outcome;
    }
    write_journal(&journal_id, plan, "verified", &format!("files={}", total_files));

    // Publish.
    ctx.phase = Phase::Publish;
    ctx.item = plan.dest_final.clone();
    ctx.report(true);
    if !win::move_path(&plan.staging, &plan.dest_final, false) {
        outcome.leftover = plan.staging.clone();
        fail(&mut outcome, "Не удалось опубликовать копию. Оригинал не изменён, копия сохранена.".into(),
             win::error_text(win::last_error()), "failed");
        return outcome;
    }
    let Some(dest_info) = win::file_info(&plan.dest_final, false) else {
        outcome.leftover = plan.dest_final.clone();
        fail(&mut outcome, "Копия опубликована, но проверить её не удалось. Оригинал не изменён.".into(),
             String::new(), "published");
        return outcome;
    };
    write_journal(&journal_id, plan, "published",
                  &format!("volume={} index={}", dest_info.serial, dest_info.index));

    // Relink.
    ctx.phase = Phase::Link;
    ctx.item = plan.source.clone();
    ctx.report(true);
    if !win::move_path(&plan.source, &plan.backup, false) {
        outcome.leftover = plan.dest_final.clone();
        fail(&mut outcome, "Копия готова, но переименовать оригинал не удалось. Исходная папка не изменена.".into(),
             win::error_text(win::last_error()), "published");
        return outcome;
    }
    write_journal(&journal_id, plan, "backup", "");
    let link_result = if faults.link_failure {
        Err(1u32)
    } else {
        win::symlink(&plan.source, &plan.dest_final, true)
    };
    if let Err(code) = link_result {
        let restored = win::move_path(&plan.backup, &plan.source, false);
        outcome.leftover = if restored { plan.dest_final.clone() } else { plan.backup.clone() };
        let detail = win::error_text(code);
        fail(&mut outcome,
             if restored {
                 "Ссылку создать не удалось. Исходная папка восстановлена, проверенная копия осталась на новом месте.".into()
             } else {
                 "Ссылку создать не удалось, и вернуть исходное имя не получилось. Данные целы в двух местах.".into()
             },
             detail, "relink-failed");
        return outcome;
    }
    if !link_still_valid(&plan.source, &plan.dest_final, dest_info.serial, dest_info.index) {
        let _ = win::delete_dir(&plan.source);
        let restored = win::move_path(&plan.backup, &plan.source, false);
        outcome.leftover = if restored { plan.dest_final.clone() } else { plan.backup.clone() };
        fail(&mut outcome, "Ссылка не прошла проверку и удалена. Исходная папка восстановлена.".into(),
             String::new(), "relink-failed");
        return outcome;
    }
    write_journal(&journal_id, plan, "linked", "");

    // Cleanup.
    ctx.phase = Phase::Cleanup;
    ctx.item = plan.dest_final.clone();
    ctx.report(true);
    if !link_still_valid(&plan.source, &plan.dest_final, dest_info.serial, dest_info.index) {
        outcome.leftover = plan.backup.clone();
        fail(&mut outcome, "Ссылка на старом месте недоступна, старый экземпляр не удалён. Данные сохранены.".into(),
             String::new(), "link-lost");
        return outcome;
    }
    let mut cleanup_ctx = Ctx::new(None);
    if let Err(error) = verify_tree(&plan.dest_final, &entries, &mut cleanup_ctx, &caps) {
        outcome.leftover = plan.backup.clone();
        fail(&mut outcome, "Копия изменилась после публикации. Старый экземпляр не удалён, данные сохранены.".into(),
             error, "cleanup-skipped");
        return outcome;
    }
    let mut durability = !faults.force_flush_failure && win::flush_volume(&plan.dest_final);
    if !durability && caps.remote && !faults.force_flush_failure {
        durability = true;
    }
    if !durability {
        outcome.ok = true;
        outcome.leftover = plan.backup.clone();
        outcome.message =
            "Перенос выполнен, ссылка работает. Подтвердить запись на диск не удалось, поэтому старый экземпляр сохранён."
                .into();
        write_journal(&journal_id, plan, "cleanup-skipped-durability", "volume-flush-failed");
        return outcome;
    }
    match delete_backup(plan, &entries, dest_info.serial, dest_info.index) {
        Ok(()) => {
            remove_journal(&journal_id);
            outcome.ok = true;
            outcome.message = "Готово. Папка перенесена, на старом месте — ссылка на новое место.".into();
            outcome
        }
        Err((error, stopped_at)) => {
            let link_lost = error.contains("перестала быть доступной");
            outcome.ok = !link_lost;
            outcome.leftover = stopped_at;
            outcome.message = if link_lost {
                "Ссылка перестала работать. Удаление остановлено, остаток сохранён.".into()
            } else {
                format!("Перенос выполнен, ссылка работает. Старый экземпляр удалён не полностью: {}", error)
            };
            outcome.detail = error;
            write_journal(&journal_id, plan, if link_lost { "link-lost" } else { "cleanup-partial" }, "");
            outcome
        }
    }
}

/// Journals that describe a transfer that may have stopped mid-way.
/// Finished outcomes (failed, cancelled, relink-failed, cleanup-*) are kept on disk but do not
/// need to be shown at startup: the user already saw their result.
const ATTENTION_STATES: [&str; 5] = ["start", "copying", "verified", "published", "backup"];

fn journal_state(text: &str) -> &str {
    text.lines().rev().find_map(|line| line.strip_prefix("state=")).unwrap_or("").trim()
}

pub fn unfinished_journals() -> Vec<std::path::PathBuf> {
    let Some(base) = journal_dir() else { return Vec::new() };
    let mut result = Vec::new();
    if let Ok(read_dir) = fs::read_dir(&base) {
        for item in read_dir.flatten() {
            let name = item.file_name().to_string_lossy().to_string();
            if !name.starts_with("journal-") || !name.ends_with(".txt") {
                continue;
            }
            let text = fs::read_to_string(item.path()).unwrap_or_default();
            let state = journal_state(&text);
            // An empty state means the journal was cut short, so it needs attention too.
            if state.is_empty() || ATTENTION_STATES.contains(&state) {
                result.push(item.path());
            }
        }
    }
    result.sort();
    result
}
