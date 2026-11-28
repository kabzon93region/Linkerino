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
    /// Fails right after a file was created and before its data is written, to prove that the
    /// object is already registered for cleanup.
    pub copy_failure_after_create: bool,
    pub verify_mismatch: bool,
    pub link_failure: bool,
    pub low_space: bool,
    pub force_flush_failure: bool,
    pub tamper_extra: bool,
    pub tamper_missing: bool,
    /// Runs a test action after the final copy verification and before any backup deletion.
    pub before_backup_delete: Option<fn(&Plan)>,
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
    /// Identity captured when the plan was approved: `execute` refuses to run on another object
    /// that merely happens to sit at the same path.
    pub source_id: win::ObjectId,
    pub dest_parent_id: win::ObjectId,
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
    /// True when the link points into the moved folder (or at the folder itself): such a link is
    /// recreated against the new location, everything else keeps its own target text.
    internal: bool,
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
    /// True when the object carries ACEs that were set explicitly, not inherited. Losing those on
    /// a filesystem without ACLs changes who can read the data, so it is treated as a real change.
    dacl_explicit: bool,
    streams: Vec<StreamInfo>,
    hash: Option<String>,
    reparse: Option<ReparseLink>,
    hardlink_primary: Option<usize>,
}

#[derive(Clone, Default)]
struct Caps {
    fs: String,
    /// True for a network share: the local write-through guarantee does not cover the server cache.
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
    win::equal_paths(path_key(left), path_key(right))
}

/// Paths are compared without a trailing separator, but a drive root keeps its form.
fn path_key(value: &str) -> &str {
    let mut text = value;
    while text.len() > 3 && text.ends_with('\\') {
        text = &text[..text.len() - 1];
    }
    text
}

fn under_or_equal(child: &str, parent: &str) -> bool {
    if parent.is_empty() || child.is_empty() {
        return false;
    }
    let child = path_key(child);
    let parent = path_key(parent);
    if same_path(child, parent) {
        return true;
    }
    // Byte slices only: cutting a UTF-8 string at a byte index used to panic on wide characters.
    win::under_prefix(child, parent)
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
    // Remember which objects the user confirmed. `execute` compares these ids again, so a folder
    // that was replaced at the same path after the preview is never touched.
    let Some(source_info) = win::file_info(&source, true) else {
        plan.valid = false;
        plan.error = format!("Не удалось прочитать исходную папку: {}", source);
        return plan;
    };
    let Some(dest_info) = win::file_info(&dest_parent, true) else {
        plan.valid = false;
        plan.error = format!("Не удалось прочитать папку назначения: {}", dest_parent);
        return plan;
    };
    plan.source_id = source_info.id();
    plan.dest_parent_id = dest_info.id();
    // Reported here so the window and the command line refuse the pair before the confirmation.
    if let Some(error) = check_journal_placement(&plan) {
        plan.valid = false;
        plan.error = error;
    }
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

fn scan_dir(root: &str, rel: &str, depth: u32, entries: &mut Vec<Entry>, ctx: &mut Ctx) -> Result<(), String> {
    if depth > 512 {
        return Err(format!("Слишком глубокая вложенность каталогов: {}", rel));
    }
    if ctx.cancel_requested() {
        return Err("Отменено пользователем".into());
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
        dacl_explicit: win::acl_has_explicit(&plain).unwrap_or(true),
        ..Default::default()
    };
    dir.streams = win::streams(&plain)
        .map_err(|code| format!("Не удалось перечислить потоки {}: {}", plain, win::error_text(code)))?
        .into_iter()
        .map(|s| StreamInfo { name: s.name, size: s.size, hash: String::new() })
        .collect();
    for stream in dir.streams.iter_mut() {
        let path = stream_path(&plain, &stream.name);
        stream.hash = hash_file(&path, ctx).map_err(|e| format!("Ошибка чтения потока {}: {}", path, e))?;
    }
    entries.push(dir);
    let read_dir = match fs::read_dir(&plain) {
        Ok(value) => value,
        Err(error) => return Err(format!("Не удалось прочитать {}: {}", plain, error)),
    };
    for item in read_dir {
        let item = item.map_err(|e| format!("Ошибка чтения {}: {}", plain, e))?;
        // A lossy conversion would silently rename the object in the copy; refuse instead.
        let name = item
            .file_name()
            .to_str()
            .map(|value| value.to_string())
            .ok_or_else(|| format!("В {} есть имя, которое нельзя прочитать как Unicode. Перенос отменён.", plain))?;
        if ctx.cancel_requested() {
            return Err("Отменено пользователем".into());
        }
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
            let target_text = win::normalize_target(&reparse.substitute);
            // A link that points into the folder is recreated against the new location; any other
            // link keeps its own target text. The target is resolved so a short 8.3 path and a long
            // path to the same folder are recognised as one place, not as two.
            let resolved = if reparse.relative {
                win::canonical(&child_plain).unwrap_or_default()
            } else {
                win::canonical(&target_text).unwrap_or_else(|| target_text.clone())
            };
            let inside_root = !resolved.is_empty()
                && (same_path(&resolved, root) || under_or_equal(&resolved, root));
            let inside_rel = if inside_root && resolved.len() >= root.len() {
                resolved[root.len()..].trim_start_matches('\\').to_string()
            } else {
                String::new()
            };
            let link_text = if inside_root { resolved.clone() } else { target_text };
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
                    internal: inside_root,
                }),
                ..Default::default()
            });
            continue;
        }
        if attrs & win::FILE_ATTRIBUTE_DIRECTORY != 0 {
            scan_dir(root, &child_rel, depth + 1, entries, ctx)?;
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
            dacl_explicit: win::acl_has_explicit(&child_plain).unwrap_or(true),
            ..Default::default()
        };
        file.streams = win::streams(&child_plain)
            .map_err(|code| format!("Не удалось перечислить потоки {}: {}", child_plain, win::error_text(code)))?
            .into_iter()
            .map(|s| StreamInfo { name: s.name, size: s.size, hash: String::new() })
            .collect();
        for stream in file.streams.iter_mut() {
            let path = stream_path(&child_plain, &stream.name);
            stream.hash = hash_file(&path, ctx).map_err(|e| format!("Ошибка чтения потока {}: {}", path, e))?;
        }
        if file.links > 1 {
            file.hash = Some(hash_file(&child_plain, ctx).map_err(|e| format!("Ошибка чтения {}: {}", child_plain, e))?);
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
    // ACL: copy the parent DACL onto the probe file and read it back. The probe never widens
    // access: a NULL (allow-everyone) DACL is never used, not even temporarily.
    if info.remote || fs_name.eq_ignore_ascii_case("ReFS") {
        caps.acl = probe_acl(&probe_file, parent);
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

/// Checks that a DACL survives a copy on this filesystem, using the parent folder's own DACL as
/// the sample: no permissive placeholder is ever written, so a failed probe cannot widen access.
fn probe_acl(probe: &str, parent: &str) -> bool {
    if !win::apply_acl(parent, probe) {
        return false;
    }
    let Some(expected) = win::acl_signature(parent) else { return false };
    let applied = win::acl_signature(probe).map(|value| value == expected).unwrap_or(false);
    applied && win::dacl_protected(probe)
}

fn attribute_mask_match(actual: u32, expected: u32, mask: u32) -> bool {
    (actual & mask) == (expected & mask)
}

fn times_match(actual: u64, expected: u64, tolerance_ms: u64) -> bool {
    actual.abs_diff(expected) <= tolerance_ms * 10_000
}

fn copy_file(
    source: &str,
    target: &str,
    entry: &mut Entry,
    ctx: &mut Ctx,
    caps: &Caps,
    created: &mut std::collections::HashSet<win::ObjectId>,
    faults: &Faults,
) -> Result<(), String> {
    let file = File::open(source).map_err(|e| format!("Не удалось открыть {}: {}", source, e))?;
    // No sharing: while the data is being written nothing else can open the new file, so the
    // inherited (possibly wider) rights never expose a half-written copy.
    let guard = match win::Guard::open_new(target, caps.acl) {
        Ok(value) => value,
        Err(code) => return Err(format!("Не удалось создать {}: {}", target, win::error_text(code))),
    };
    // Registered right after creation: a failure below must still be able to clean this object up.
    let created_id = guard.id().ok_or_else(|| format!("Не удалось подтвердить {}", target))?;
    created.insert(created_id);
    if faults.copy_failure_after_create {
        return Err("Тестовый сбой после создания файла".into());
    }
    let mut hasher = Sha256::new();
    let mut reader = std::io::BufReader::new(file);
    let mut buffer = vec![0u8; 1 << 20];
    {
        let mut output = guard.as_file();
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
    }
    entry.hash = Some(format!("{:x}", hasher.finalize()));
    // Rights and dates are applied through the same exclusive handle, before it is closed.
    if caps.acl && !guard.set_dacl_from(source) {
        return Err(format!("Не удалось сохранить права доступа для {}", target));
    }
    if !guard.set_basic(entry.created, entry.modified, entry.modified, Some(entry.attrs & caps.attr_mask)) {
        return Err(format!("Не удалось сохранить даты и атрибуты {}", target));
    }
    drop(guard);
    if caps.streams {
        for stream in entry.streams.iter_mut() {
            let source_stream = stream_path(source, &stream.name);
            let target_stream = stream_path(target, &stream.name);
            stream.hash = copy_stream(&source_stream, &target_stream, ctx)
                .map_err(|e| format!("Ошибка копирования потока {}: {}", source_stream, e))?;
        }
        // Writing a stream changes the modification time, so the recorded one is restored again.
        if !win::set_times(target, entry.created, entry.modified, entry.modified) {
            return Err(format!("Не удалось сохранить даты {}", target));
        }
    }
    Ok(())
}

fn copy_reparse(
    target: &str,
    link: &ReparseLink,
    created: &mut std::collections::HashSet<win::ObjectId>,
) -> Result<(), String> {
    if link.tag == 0xA000000C {
        win::symlink(target, &link.link_text, link.is_dir)
            .map_err(|code| format!("Не удалось создать ссылку {}: {}", target, win::error_text(code)))?;
        match win::object_id(target, true) {
            Some(id) => created.insert(id),
            None => return Err(format!("Не удалось подтвердить ссылку {}", target)),
        };
        return Ok(());
    }
    if link.tag == 0xA0000003 {
        if !win::create_dir_new(target) {
            return Err(format!("Не удалось создать каталог для junction {}", target));
        }
        // Registered before the reparse data is written, so a failure below can still clean up.
        match win::object_id(target, true) {
            Some(id) => created.insert(id),
            None => return Err(format!("Не удалось подтвердить каталог junction {}", target)),
        };
        // An internal junction gets a freshly built block that points at the new location; an
        // external one is written back exactly as it was.
        let block = if link.internal {
            win::junction_block(&link.link_text)
        } else {
            link.raw.clone()
        };
        if !win::write_junction(target, &block) {
            return Err(format!("Не удалось создать junction {}", target));
        }
        return Ok(());
    }
    Err(format!("Неподдерживаемый тип ссылки: {}", target))
}

fn copy_tree(
    plan: &Plan,
    entries: &mut [Entry],
    ctx: &mut Ctx,
    faults: &Faults,
    caps: &Caps,
    created: &mut std::collections::HashSet<win::ObjectId>,
) -> Result<(), String> {
    for index in 0..entries.len() {
        if ctx.cancel_requested() {
            return Err("Отменено пользователем".into());
        }
        if !entries[index].is_dir || entries[index].reparse.is_some() {
            continue;
        }
        let rel = entries[index].rel.clone();
        let target = if rel.is_empty() { plan.staging.clone() } else { win::join(&plan.staging, &rel) };
        // An object that already exists is never accepted: the copy must consist of new objects only.
        // The staging root itself was created and identified by `execute`, so it is reused as is.
        if !rel.is_empty() {
            if !win::create_dir_new(&target) {
                return Err(format!("Не удалось создать каталог {}", target));
            }
            // Remember exactly which objects this operation created: cleanup may delete only these.
            match win::object_id(&target, true) {
                Some(id) => { created.insert(id); }
                None => return Err(format!("Не удалось подтвердить каталог {}", target)),
            }
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
        let Some(mut link) = entries[index].reparse.clone() else { continue };
        let target = win::join(&plan.staging, &entries[index].rel);
        // A link that points into the moved folder must point at the future location of that
        // object, not at the old path: the old path only works while the source link exists.
        if link.internal {
            link.link_text = win::join(&plan.dest_final, &link.inside_rel);
        }
        if ctx.cancel_requested() {
            return Err("Отменено пользователем".into());
        }
        ctx.item = entries[index].rel.clone();
        ctx.report(false);
        copy_reparse(&target, &link, created)?;
        entries[index].reparse = Some(link);
    }
    for index in 0..entries.len() {
        if entries[index].is_dir || entries[index].reparse.is_some() {
            continue;
        }
        if faults.copy_failure {
            return Err("Тестовый сбой копирования".into());
        }
        if ctx.cancel_requested() {
            return Err("Отменено пользователем".into());
        }
        let rel = entries[index].rel.clone();
        let source = win::join(&plan.source, &rel);
        let target = win::join(&plan.staging, &rel);
        ctx.item = rel.clone();
        ctx.report(false);
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
            copy_file(&source, &target, &mut copy, ctx, caps, created, faults)?;
            entries[index].hash = copy.hash.clone();
            entries[index].streams = copy.streams.clone();
        } else {
            // A hard link is a new name for an object that is already tracked; remember the name's
            // own identity as well so the cleanup can recognise it.
            if let Some(id) = win::object_id(&target, true) {
                created.insert(id);
            }
        }
        ctx.files_done += 1;
        ctx.report(false);
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
    // The kind of the object (file or folder link) must survive the copy.
    if (attrs & win::FILE_ATTRIBUTE_DIRECTORY != 0) != link.is_dir {
        return Err(format!("Вид ссылки (файл или каталог) не совпадает: {}", plain));
    }
    // `link_text` is exactly what this run created: the future path for an internal link, the
    // original target text for an external one.
    let expected = if link.link_text.is_empty() {
        win::normalize_target(&link.substitute)
    } else {
        link.link_text.clone()
    };
    if !win::normalize_target(&actual.substitute).eq_ignore_ascii_case(&expected) {
        return Err(format!("Цель ссылки не совпадает: {} -> {}", plain, actual.substitute));
    }
    // A link that points into the moved folder is recreated absolute against the new location;
    // every other link keeps the form it had (relative stays relative).
    let expected_relative = if link.internal { false } else { link.relative };
    if actual.relative != expected_relative {
        return Err(format!("Вид ссылки (относительная или абсолютная) не совпадает: {}", plain));
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
            // Order is not part of the meaning: names are compared as a set.
            let mut actual_names: Vec<&str> = actual.iter().map(|stream| stream.name.as_str()).collect();
            let mut expected_names: Vec<&str> = entry.streams.iter().map(|stream| stream.name.as_str()).collect();
            actual_names.sort();
            expected_names.sort();
            if actual_names != expected_names {
                return Err(format!("Имена потоков файла не совпадают: {}", plain));
            }
            for stream in entry.streams.iter() {
                let path = stream_path(&plain, &stream.name);
                let hash = hash_file(&path, ctx).map_err(|e| format!("Ошибка сверки потока {}: {}", path, e))?;
                if hash != stream.hash {
                    return Err(format!("Содержимое потока не совпадает: {}", path));
                }
            }
        }
    } else {
        // Directory attributes are compared where the filesystem keeps them; the read-only flag is
        // not applied to folders, so it is masked out.
        if !attribute_mask_match(info.attrs, entry.attrs, caps.attr_mask & !win::FILE_ATTRIBUTE_READONLY) {
            return Err(format!("Атрибуты каталога не совпадают: {}", plain));
        }
        if caps.dir_streams {
            let actual = win::streams(&plain)
                .map_err(|code| format!("Не удалось перечислить потоки {}: {}", plain, win::error_text(code)))?;
            if actual.len() != entry.streams.len() {
                return Err(format!("Набор потоков каталога не совпадает: {}", plain));
            }
            let mut actual_names: Vec<&str> = actual.iter().map(|stream| stream.name.as_str()).collect();
            let mut expected_names: Vec<&str> = entry.streams.iter().map(|stream| stream.name.as_str()).collect();
            actual_names.sort();
            expected_names.sort();
            if actual_names != expected_names {
                return Err(format!("Имена потоков каталога не совпадают: {}", plain));
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

fn collect_paths(root: &str, ctx: &mut Ctx) -> Result<Vec<String>, String> {
    fn walk(root: &str, rel: &str, out: &mut Vec<String>, ctx: &mut Ctx) -> Result<(), String> {
        if ctx.cancel_requested() {
            return Err("Отменено пользователем".into());
        }
        out.push(rel.to_string());
        let plain = if rel.is_empty() { root.to_string() } else { win::join(root, rel) };
        let read = fs::read_dir(&plain).map_err(|e| format!("Не удалось прочитать {}: {}", plain, e))?;
        for item in read {
            if ctx.cancel_requested() {
                return Err("Отменено пользователем".into());
            }
            let item = item.map_err(|e| format!("Ошибка чтения {}: {}", plain, e))?;
            // A lossy name would silently compare a different object than the one on disk.
            let name = item
                .file_name()
                .to_str()
                .map(|value| value.to_string())
                .ok_or_else(|| format!("В {} есть имя, которое нельзя прочитать как Unicode", plain))?;
            let child_rel = if rel.is_empty() { name.clone() } else { win::join(rel, &name) };
            let child_plain = win::join(&plain, &name);
            let attrs = win::attributes(&child_plain)
                .ok_or_else(|| format!("Не удалось прочитать атрибуты {}", child_plain))?;
            out.push(child_rel.clone());
            if attrs & win::FILE_ATTRIBUTE_DIRECTORY != 0 && attrs & win::FILE_ATTRIBUTE_REPARSE_POINT == 0 {
                walk(root, &child_rel, out, ctx)?;
            }
        }
        Ok(())
    }
    let mut result = Vec::new();
    walk(root, "", &mut result, ctx)?;
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
fn verify_path_set(root: &str, entries: &[Entry], ctx: &mut Ctx) -> Result<(), String> {
    let mut expected: Vec<String> = entries.iter().map(|entry| entry.rel.clone()).collect();
    let mut actual = collect_paths(root, ctx)?;
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
    verify_path_set(root, entries, ctx)?;
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

fn verify_source_unchanged(plan: &Plan, entries: &[Entry], ctx: &mut Ctx) -> Result<(), String> {
    for entry in entries {
        if ctx.cancel_requested() {
            return Err("Отменено пользователем".into());
        }
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
            // The same counter as the rest of the pass, so cancellation is noticed while hashing.
            let hash = hash_file(&plain, ctx).map_err(|e| format!("Ошибка сверки {}: {}", plain, e))?;
            if Some(&hash) != entry.hash.as_ref() {
                return Err(format!("Содержимое исходного файла изменилось: {}", plain));
            }
        }
    }
    Ok(())
}

/// Where the recovery records live: an explicit override or the per-user folder. Nothing is
/// created here, so the placement can be checked before the first write.
fn journal_path() -> Option<std::path::PathBuf> {
    match std::env::var("LINKERINO_JOURNAL_DIR") {
        Ok(custom) if !custom.trim().is_empty() => Some(Path::new(custom.trim()).to_path_buf()),
        _ => Some(Path::new(&std::env::var("LOCALAPPDATA").ok()?).join("Linkerino")),
    }
}

/// Resolves a path that may not exist yet: the deepest existing ancestor is canonicalised, so a
/// short 8.3 name or another letter case cannot hide the real location, and the missing tail is
/// appended exactly as written.
fn resolve_future(raw: &Path) -> Option<String> {
    let absolute = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(raw)
    };
    let mut existing = absolute.as_path();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    // The depth guard keeps a path form that never reaches a root from hanging the caller.
    for _ in 0..64 {
        if let Some(base) = win::canonical(&existing.to_string_lossy()) {
            let mut resolved = std::path::PathBuf::from(base);
            for part in tail.iter().rev() {
                resolved.push(part);
            }
            return Some(resolved.to_string_lossy().to_string());
        }
        tail.push(existing.file_name()?.to_os_string());
        existing = existing.parent()?;
    }
    None
}

/// The journal is written while the source name is being moved, so it must never live inside the
/// folder that is being moved: a record written after the rename would recreate the old path as a
/// real directory, and the link or the rollback would then fail. The check runs before any write,
/// so the source, the destination and the disk stay untouched when it fails.
fn check_journal_placement(plan: &Plan) -> Option<String> {
    let journal = journal_path()?;
    // A folder that cannot be resolved cannot be proven to lie outside the moved tree, so the
    // answer is "no" for the move rather than a silent risk.
    let Some(resolved) = resolve_future(&journal) else {
        return Some(format!(
            "Не удалось определить расположение папки журналов: {}. Укажите существующую папку журналов. Перенос не начат, данные не тронуты.",
            journal.display()
        ));
    };
    for (label, victim) in [("переносимой папки", &plan.source), ("будущей копии", &plan.dest_final)] {
        if under_or_equal(&resolved, victim) {
            return Some(format!(
                "Папка журналов находится внутри {}: {}. Укажите другую папку журналов, иначе запись журнала займёт старый путь. Перенос не начат, данные не тронуты.",
                label, resolved
            ));
        }
    }
    None
}

fn journal_root(create: bool) -> Option<std::path::PathBuf> {
    let path = journal_path()?;
    if create {
        fs::create_dir_all(&path).ok()?;
        return Some(path);
    }
    // "No folder yet" and "cannot look inside" are different answers: only a missing folder means
    // there is nothing to report.
    match fs::metadata(&path) {
        Ok(meta) if meta.is_dir() => Some(path),
        Ok(_) => None,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => Some(path),
    }
}

/// Recovery record of one transfer. Every field that a person would need to finish or undo the
/// operation by hand is stored here, and every update is atomic and durable.
struct Journal {
    id: String,
    source: String,
    source_id: win::ObjectId,
    dest: String,
    dest_id: Option<win::ObjectId>,
    staging: String,
    backup: String,
    files: u64,
}

fn escape_value(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            _ => result.push(character),
        }
    }
    result
}

fn unescape_value(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            result.push(character);
            continue;
        }
        match characters.next() {
            Some('n') => result.push('\n'),
            Some('r') => result.push('\r'),
            Some(other) => result.push(other),
            None => result.push('\\'),
        }
    }
    result
}

fn id_text(id: win::ObjectId) -> String {
    format!("{:x}:{:x}", id.serial, id.index)
}

impl Journal {
    fn new(plan: &Plan) -> Journal {
        Journal {
            id: guid(),
            source: plan.source.clone(),
            source_id: plan.source_id,
            dest: plan.dest_final.clone(),
            dest_id: None,
            staging: plan.staging.clone(),
            backup: plan.backup.clone(),
            files: 0,
        }
    }

    fn file_name(&self) -> String {
        format!("journal-{}.txt", self.id)
    }

    fn text(&self, state: &str, note: &str) -> String {
        let mut text = String::new();
        text.push_str("version=3\n");
        text.push_str(&format!("id={}\n", escape_value(&self.id)));
        text.push_str(&format!("state={}\n", escape_value(state)));
        text.push_str(&format!("source={}\n", escape_value(&self.source)));
        text.push_str(&format!("sourceid={}\n", id_text(self.source_id)));
        text.push_str(&format!("dest={}\n", escape_value(&self.dest)));
        text.push_str(&format!(
            "destid={}\n",
            self.dest_id.map(id_text).unwrap_or_default()
        ));
        text.push_str(&format!("staging={}\n", escape_value(&self.staging)));
        text.push_str(&format!("backup={}\n", escape_value(&self.backup)));
        text.push_str(&format!("files={}\n", self.files));
        text.push_str(&format!("note={}\n", escape_value(note)));
        text
    }

    /// Writes the record through a temporary file and a write-through rename, so a reader never
    /// sees a half-written journal and a power loss cannot leave the old state behind.
    fn save(&self, state: &str, note: &str) -> Result<(), String> {
        let Some(dir) = journal_root(true) else {
            return Err("Не удалось открыть папку журналов".into());
        };
        let path = dir.join(self.file_name());
        let temp = dir.join(format!("journal-{}.tmp", self.id));
        let write = || -> Result<(), String> {
            let mut file = File::create(&temp).map_err(|error| format!("журнал: {}", error))?;
            file.write_all(self.text(state, note).as_bytes())
                .map_err(|error| format!("журнал: {}", error))?;
            file.sync_all().map_err(|error| format!("журнал: {}", error))?;
            Ok(())
        };
        if let Err(error) = write() {
            let _ = fs::remove_file(&temp);
            return Err(error);
        }
        if !win::move_path_through(&temp.to_string_lossy(), &path.to_string_lossy(), true) {
            let _ = fs::remove_file(&temp);
            return Err(format!("журнал: {}", win::error_text(win::last_error())));
        }
        Ok(())
    }

    fn finish(&self, state: &str, note: &str) {
        if self.save(state, note).is_ok() {
            if let Some(dir) = journal_root(false) {
                let _ = fs::remove_file(dir.join(self.file_name()));
            }
        }
    }
}

/// Removes the temporary folder, but only the objects this run created. Anything else is left in
/// place and the path stays visible as the leftover.
fn cleanup_staging(
    outcome: &mut Outcome,
    plan: &Plan,
    staging_id: win::ObjectId,
    created: &std::collections::HashSet<win::ObjectId>,
) {
    if !remove_tree(&plan.staging, staging_id, created) {
        outcome.leftover = plan.staging.clone();
    }
}

/// Guards the temporary folder: cleanup only removes objects that this operation created, and the
/// whole traversal is done through held handles, so nothing can be renamed or replaced under it.
fn remove_tree(path: &str, expected: win::ObjectId, created: &std::collections::HashSet<win::ObjectId>) -> bool {
    remove_tree_held(path, Some(expected), created)
}

fn remove_tree_held(
    path: &str,
    expected: Option<win::ObjectId>,
    created: &std::collections::HashSet<win::ObjectId>,
) -> bool {
    // The handle is opened without FILE_SHARE_DELETE: while it is held, this directory cannot be
    // renamed or replaced, so the names below it keep pointing inside the tree we are cleaning.
    let mut guard = match win::Guard::open_held(
        path,
        win::READ_DATA_ACCESS | win::READ_ATTRIBUTES_ACCESS | win::DELETE_ACCESS,
    ) {
        Ok(value) => value,
        Err(_) => return !win::path_exists(path),
    };
    let Some(handle_id) = guard.id() else { return false };
    if let Some(expected) = expected {
        if handle_id != expected {
            return false;
        }
    }
    // A foreign object inside the temporary folder is not ours: keep it and stop, so the path can
    // be shown to the user instead of being deleted silently.
    if !created.contains(&handle_id) {
        return false;
    }
    let Some(info) = guard.info() else { return false };
    if info.attrs & win::FILE_ATTRIBUTE_DIRECTORY == 0 || info.attrs & win::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        // A file or a link is deleted through this very handle; a link is never followed.
        let removed = guard.remove().is_ok();
        drop(guard);
        return removed && !win::path_exists(path);
    }
    let mut children = Vec::new();
    match fs::read_dir(path) {
        Ok(read_dir) => {
            for item in read_dir.flatten() {
                match item.file_name().to_str() {
                    Some(name) => children.push(name.to_string()),
                    None => return false,
                }
            }
        }
        Err(_) => return false,
    }
    for name in children {
        if !remove_tree_held(&win::join(path, &name), None, created) {
            return false;
        }
    }
    // Still the same directory on the same handle, and it is empty now.
    let removed = guard.remove().is_ok();
    drop(guard);
    removed && !win::path_exists(path)
}

/// Re-lists the streams and re-reads every recorded one through its own handle. A stream that was
/// added, removed or changed since the scan stops the delete.
fn check_streams(path: &str, expected: &[StreamInfo], expected_id: win::ObjectId) -> Result<(), String> {
    if expected.is_empty() {
        if win::streams(path).map(|actual| actual.is_empty()).unwrap_or(false) {
            return Ok(());
        }
        return Err(format!("У объекта появились новые потоки: {}", path));
    }
    let actual = win::streams(path)
        .map_err(|code| format!("Не удалось перечислить потоки {}: {}", path, win::error_text(code)))?;
    if actual.len() != expected.len() {
        return Err(format!("Набор потоков изменился: {}", path));
    }
    let mut actual_names: Vec<&str> = actual.iter().map(|stream| stream.name.as_str()).collect();
    let mut expected_names: Vec<&str> = expected.iter().map(|stream| stream.name.as_str()).collect();
    actual_names.sort();
    expected_names.sort();
    if actual_names != expected_names {
        return Err(format!("Имена потоков изменились: {}", path));
    }
    for stream in expected {
        let stream_file = stream_path(path, &stream.name);
        let guard = win::Guard::open(&stream_file, win::READ_DATA_ACCESS | win::READ_ATTRIBUTES_ACCESS, false)
            .map_err(|code| format!("Не удалось открыть поток {}: {}", stream_file, win::error_text(code)))?;
        // A stream path resolves to the base object, so its identity must match that object.
        if guard.id() != Some(expected_id) {
            return Err(format!("Поток принадлежит другому объекту: {}", stream_file));
        }
        let mut ctx = Ctx::new(None);
        let hash = {
            let file = guard.as_file();
            hash_stream(&*file, &mut ctx).map(|(value, _)| value)
        }
        .map_err(|error| format!("Ошибка сверки потока {}: {}", stream_file, error))?;
        if hash != stream.hash {
            return Err(format!("Содержимое потока изменилось: {}", stream_file));
        }
    }
    Ok(())
}

/// Why the cleanup stopped. The kind decides what the report says and where the data is left.
enum CleanupStop {
    /// The link no longer points at the published copy.
    LinkLost(String),
    /// The published copy no longer matches what was verified, so its backup must stay.
    CopyChanged(String),
    /// The backup itself could not be checked or removed.
    Backup(String),
}

/// Deletes the backup only after every object has been re-checked through the same handle that is
/// then used to delete it: verification and deletion can never refer to different objects. The
/// whole copy is verified once before anything is deleted, then every object is checked again and
/// held without write sharing right before its backup counterpart is removed, so a program writing
/// through the link can neither hide a change nor make the checked data disappear.
fn delete_backup(
    plan: &Plan,
    entries: &[Entry],
    dest_id: win::ObjectId,
    caps: &Caps,
) -> Result<(), (CleanupStop, String)> {
    let stop = |message: String| (CleanupStop::Backup(message), plan.backup.clone());
    let backup_at = |message: String, path: &str| (CleanupStop::Backup(message), path.to_string());
    let copy_changed = |message: String| (CleanupStop::CopyChanged(message), plan.backup.clone());
    let mut ctx = Ctx::new(None);
    // All or nothing: a copy that no longer matches what was verified keeps the whole backup, and
    // this pass also compares hard-link groups again.
    verify_tree(&plan.dest_final, entries, &mut ctx, caps)
        .map_err(|error| copy_changed(format!("Копия изменилась после сверки: {}", error)))?;
    let mut processed = 0usize;
    for entry in entries.iter().rev() {
        if processed % 32 == 0 && !link_still_valid(&plan.source, &plan.dest_final, dest_id) {
            return Err((
                CleanupStop::LinkLost(format!("Ссылка на новое место перестала быть доступной: {}", plan.source)),
                plan.backup.clone(),
            ));
        }
        processed += 1;
        let dest_plain =
            if entry.rel.is_empty() { plan.dest_final.clone() } else { win::join(&plan.dest_final, &entry.rel) };
        // The hold is what makes the check below meaningful: while the object is open without write
        // sharing nothing can change it or replace it before its backup is deleted. A plain folder
        // is not held — it carries no data of its own and every file inside is held with its entry;
        // a link is held, because its target is what the copy actually exposes.
        let _held = if entry.is_dir && entry.reparse.is_none() {
            None
        } else {
            let access = if entry.reparse.is_some() {
                win::READ_ATTRIBUTES_ACCESS
            } else {
                win::READ_DATA_ACCESS | win::READ_ATTRIBUTES_ACCESS
            };
            Some(win::Guard::open_no_write(&dest_plain, access, false).map_err(|code| {
                copy_changed(format!(
                    "Копию нельзя защитить от изменений ({}): {}",
                    dest_plain,
                    win::error_text(code)
                ))
            })?)
        };
        verify_entry(&plan.dest_final, entry, &mut ctx, caps)
            .map_err(|error| copy_changed(format!("Копия изменилась после сверки: {}", error)))?;
        let plain = if entry.rel.is_empty() { plan.backup.clone() } else { win::join(&plan.backup, &entry.rel) };
        let expected = win::ObjectId { serial: entry.serial, index: entry.index };
        let access = win::READ_DATA_ACCESS | win::READ_ATTRIBUTES_ACCESS | win::WRITE_ATTRIBUTES_ACCESS
            | win::DELETE_ACCESS;
        let mut guard = win::Guard::open(&plain, access, false)
            .map_err(|code| backup_at(format!("Не удалось открыть объект резерва {}: {}", plain, win::error_text(code)), &plain))?;
        let info = guard
            .info()
            .ok_or_else(|| backup_at(format!("Не удалось прочитать {}", plain), &plain))?;

        if entry.reparse.is_some() {
            if info.attrs & win::FILE_ATTRIBUTE_REPARSE_POINT == 0 {
                return Err(stop(format!("В резерве появился обычный объект вместо ссылки: {}", plain)));
            }
            let link = entry.reparse.as_ref().unwrap();
            let actual = guard.reparse().map_err(|code| {
                backup_at(format!("Не удалось прочитать ссылку в резерве {}: {}", plain, win::error_text(code)), &plain)
            })?;
            if actual.tag != link.tag
                || !win::normalize_target(&actual.substitute)
                    .eq_ignore_ascii_case(&win::normalize_target(&link.substitute))
            {
                return Err(stop(format!("Ссылка в резерве изменилась: {}", plain)));
            }
            guard
                .remove()
                .map_err(|code| backup_at(format!("Не удалось удалить ссылку {}: {}", plain, win::error_text(code)), &plain))?;
            drop(guard);
            if win::path_exists(&plain) {
                return Err(stop(format!("Ссылка осталась на месте: {}", plain)));
            }
            continue;
        }

        if info.attrs & win::FILE_ATTRIBUTE_DIRECTORY != 0 {
            if info.attrs & win::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(stop(format!("Тип объекта в резерве изменился: {}", plain)));
            }
            if info.id() != expected {
                return Err(stop(format!("Каталог резерва подменён: {}", plain)));
            }
            check_streams(&plain, &entry.streams, expected).map_err(|error| backup_at(error, &plain))?;
            // A directory is deleted only when it is empty: an added object must stop the cleanup.
            if let Ok(mut read_dir) = fs::read_dir(&plain) {
                if read_dir.next().is_some() {
                    return Err(stop(format!("В каталоге резерва появились новые объекты: {}", plain)));
                }
            }
            guard
                .remove()
                .map_err(|code| backup_at(format!("Не удалось удалить каталог резерва {}: {}", plain, win::error_text(code)), &plain))?;
            drop(guard);
            if win::path_exists(&plain) {
                return Err(stop(format!("Каталог резерва остался на месте: {}", plain)));
            }
            continue;
        }

        if info.attrs & win::FILE_ATTRIBUTE_DIRECTORY != 0 {
            return Err(stop(format!("Тип объекта в резерве изменился: {}", plain)));
        }
        if info.id() != expected || info.size != entry.size || info.modified != entry.modified {
            return Err(stop(format!("Файл резерва изменился: {}", plain)));
        }
        // The hash is read from the handle that is going to delete this very object.
        let mut backup_ctx = Ctx::new(None);
        let hash = {
            let file = guard.as_file();
            hash_stream(&*file, &mut backup_ctx).map(|(value, _)| value)
        }
        .map_err(|error| backup_at(format!("Ошибка сверки {}: {}", plain, error), &plain))?;
        if Some(&hash) != entry.hash.as_ref() {
            return Err(stop(format!("Содержимое файла резерва изменилось: {}", plain)));
        }
        check_streams(&plain, &entry.streams, expected).map_err(|error| backup_at(error, &plain))?;
        guard
            .remove()
            .map_err(|code| backup_at(format!("Не удалось удалить файл резерва {}: {}", plain, win::error_text(code)), &plain))?;
        drop(guard);
        if win::path_exists(&plain) {
            return Err(stop(format!("Файл резерва остался на месте: {}", plain)));
        }
    }
    Ok(())
}

fn link_still_valid(link: &str, target: &str, dest_id: win::ObjectId) -> bool {
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
    win::object_id(link, false) == Some(dest_id)
}

/// Confirms that the plan still describes the objects the user saw in the preview. A path that now
/// leads to another folder, or a destination that got occupied in the meantime, stops the transfer
/// before anything is written.
fn revalidate_plan(plan: &Plan) -> Result<(), String> {
    if plan.source.is_empty() || plan.dest_parent.is_empty() || plan.dest_final.is_empty() {
        return Err("План переноса неполон.".into());
    }
    if plan.source.len() <= 3 {
        return Err(format!("Нельзя переносить корень диска: {}", plan.source));
    }
    let Some(source) = win::file_info(&plan.source, true) else {
        return Err(format!("Исходная папка недоступна: {}", plan.source));
    };
    if source.attrs & win::FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(format!("Исходный путь больше не папка: {}", plan.source));
    }
    if source.attrs & win::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!("Исходная папка стала ссылкой: {}", plan.source));
    }
    if source.id() != plan.source_id {
        return Err(format!("Исходная папка была заменена после проверки: {}", plan.source));
    }
    let Some(dest) = win::file_info(&plan.dest_parent, true) else {
        return Err(format!("Папка назначения недоступна: {}", plan.dest_parent));
    };
    if dest.attrs & win::FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(format!("Место назначения больше не папка: {}", plan.dest_parent));
    }
    if dest.attrs & win::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!("Место назначения стало ссылкой: {}", plan.dest_parent));
    }
    if dest.id() != plan.dest_parent_id {
        return Err(format!("Папка назначения была заменена после проверки: {}", plan.dest_parent));
    }
    if win::path_exists(&plan.dest_final) {
        return Err(format!("На новом месте уже есть объект: {}", plan.dest_final));
    }
    let Some(source_now) = win::canonical(&plan.source) else {
        return Err(format!("Не удалось открыть исходную папку: {}", plan.source));
    };
    let Some(dest_now) = win::canonical(&plan.dest_parent) else {
        return Err(format!("Не удалось открыть папку назначения: {}", plan.dest_parent));
    };
    if under_or_equal(&dest_now, &source_now) {
        return Err("Папка назначения находится внутри переносимой папки.".into());
    }
    if under_or_equal(&source_now, &plan.dest_final) {
        return Err("Исходная папка находится внутри папки назначения.".into());
    }
    if critical_dirs().iter().any(|dir| under_or_equal(&source_now, dir)) {
        return Err(format!("Нельзя переносить системные каталоги Windows: {}", source_now));
    }
    if let Ok(profile) = std::env::var("USERPROFILE") {
        if let Some(canonical_profile) = win::canonical(&profile) {
            if same_path(&source_now, &canonical_profile) {
                return Err(format!("Нельзя переносить папку профиля пользователя целиком: {}", source_now));
            }
        }
    }
    Ok(())
}

pub fn execute(plan: &Plan, sink: Option<&dyn Sink>, faults: &Faults) -> Outcome {
    let mut outcome = Outcome::default();
    if !plan.valid {
        outcome.message = "Проверка путей не пройдена.".into();
        outcome.detail = plan.error.clone();
        return outcome;
    }
    // The plan was approved for concrete objects. If either path now points at another object,
    // nothing is changed and the caller has to preview and confirm again.
    if let Err(error) = revalidate_plan(plan) {
        outcome.message = "Условия переноса изменились после проверки. Данные не тронуты.".into();
        outcome.detail = error;
        return outcome;
    }
    let mut ctx = Ctx::new(sink);
    let mut journal = Journal::new(plan);
    // The placement is checked again here: the environment can differ from the one that built the
    // plan, and this is the last point before the first write.
    if let Some(error) = check_journal_placement(plan) {
        outcome.message =
            "Папка журналов расположена недопустимо, поэтому перенос не начат. Данные не тронуты.".into();
        outcome.detail = error;
        return outcome;
    }
    // Without a recovery record the operation must not start: if anything goes wrong later,
    // nobody could tell what happened to which folder.
    if let Err(error) = journal.save("start", "") {
        outcome.message = "Не удалось записать журнал восстановления. Перенос не начат, данные не тронуты.".into();
        outcome.detail = error;
        return outcome;
    }

    let fail = |outcome: &mut Outcome, journal: &Journal, message: String, detail: String, state: &str| {
        outcome.ok = false;
        outcome.message = message;
        outcome.detail = detail.clone();
        let _ = journal.save(state, &format!("error={}", detail));
    };

    // Preflight: can we create a directory symlink next to the source?
    ctx.phase = Phase::Validate;
    ctx.item = "Проверка прав на ссылку".into();
    ctx.report(true);
    let probe_link = win::join(&plan.source_parent, &format!(".linkerino-probe-{}", guid()));
    if let Err(code) = win::symlink(&probe_link, &plan.dest_final, true) {
        fail(&mut outcome, &journal, "Не удалось проверить возможность создать ссылку. Перенос не начат, данные не тронуты.".into(),
             win::error_text(code), "failed");
        outcome.needs_elevation = code == 1314;
        return outcome;
    }
    let _ = win::delete_dir(&probe_link);

    // The staging folder is created by this run and never adopted: an existing object is a failure.
    if !win::create_dir_new(&plan.staging) {
        fail(&mut outcome, &journal, "Не удалось создать временную папку. Данные не тронуты.".into(),
             format!("{}: {}", plan.staging, win::error_text(win::last_error())), "failed");
        return outcome;
    }
    let Some(staging_id) = win::object_id(&plan.staging, false) else {
        fail(&mut outcome, &journal, "Не удалось подтвердить временную папку. Данные не тронуты.".into(),
             plan.staging.clone(), "failed");
        return outcome;
    };
    let mut created: std::collections::HashSet<win::ObjectId> = std::collections::HashSet::new();
    created.insert(staging_id);
    // The temporary tree gets the rights of the original root immediately, so the names being
    // copied are never exposed through a wider inherited DACL.
    if !win::apply_acl(&plan.source, &plan.staging) {
        ctx.item = "Не удалось применить права доступа к временной папке".into();
        ctx.report(true);
    }
    let _ = journal.save("copying", "");

    // Scan.
    ctx.phase = Phase::Scan;
    ctx.item = plan.source.clone();
    ctx.report(true);
    let mut entries: Vec<Entry> = Vec::new();
    if let Err(error) = scan_dir(&plan.source, "", 0, &mut entries, &mut ctx) {
        cleanup_staging(&mut outcome, plan, staging_id, &created);
        if ctx.cancelled {
            outcome.cancelled = true;
            outcome.message = "Отменено до изменения исходной папки. Оригинал на месте.".into();
            outcome.detail = error.clone();
            let _ = journal.save("cancelled", &format!("error={}", error));
            return outcome;
        }
        fail(&mut outcome, &journal, "Перенос остановлен до копирования: неподдерживаемые объекты. Оригинал не изменён.".into(),
             error, "failed");
        return outcome;
    }
    build_hardlink_groups(&mut entries);
    let caps = match probe_caps(&plan.dest_parent) {
        Ok(value) => value,
        Err(error) => {
            cleanup_staging(&mut outcome, plan, staging_id, &created);
            fail(&mut outcome, &journal, "Новое место недоступно для записи. Оригинал не изменён.".into(), error, "failed");
            return outcome;
        }
    };
    let has_links = entries.iter().any(|e| e.reparse.is_some());
    if has_links && !caps.reparse {
        cleanup_staging(&mut outcome, plan, staging_id, &created);
        fail(&mut outcome, &journal, "В папке есть ссылки, а на новом месте их создать нельзя. Оригинал не изменён.".into(),
             format!("Файловая система назначения ({}) не поддерживает ссылки. Выберите диск NTFS.", caps.fs), "failed");
        return outcome;
    }
    // On a network share the volume serial and file index come from the server and need not be
    // unique, so two different files could look like one hard-linked object. The source matters as
    // much as the destination here: the identifiers are read there. Splitting them into separate
    // copies is the safe choice: content is preserved, only the link count changes.
    let source_remote = win::volume_info(&plan.source).map(|value| value.remote).unwrap_or(false);
    let grouped_links = entries.iter().filter(|entry| entry.hardlink_primary.is_some()).count();
    if caps.remote || source_remote {
        for entry in entries.iter_mut() {
            entry.hardlink_primary = None;
        }
    }
    // Data-bearing properties are never dropped silently: a destination without streams cannot
    // hold them, so the transfer stops while the original is still untouched.
    let files_with_streams = entries
        .iter()
        .filter(|entry| !entry.is_dir && entry.reparse.is_none() && !entry.streams.is_empty())
        .count();
    if !caps.streams && files_with_streams > 0 {
        cleanup_staging(&mut outcome, plan, staging_id, &created);
        fail(&mut outcome, &journal,
             "В папке есть именованные потоки, а новое место их не поддерживает. Оригинал не изменён.".into(),
             format!("Файлов с потоками: {}. Файловая система назначения: {}.", files_with_streams, caps.fs),
             "failed");
        return outcome;
    }
    let dirs_with_streams = entries.iter().filter(|entry| entry.is_dir && !entry.streams.is_empty()).count();
    if !caps.dir_streams && dirs_with_streams > 0 {
        cleanup_staging(&mut outcome, plan, staging_id, &created);
        fail(&mut outcome, &journal,
             "В папке есть потоки каталогов, а новое место их не поддерживает. Оригинал не изменён.".into(),
             format!("Каталогов с потоками: {}. Файловая система назначения: {}.", dirs_with_streams, caps.fs),
             "failed");
        return outcome;
    }
    let mut notes = String::new();
    if !caps.acl && entries.iter().any(|entry| entry.dacl_explicit) {
        notes.push_str("Права доступа: на новом месте их нельзя сохранить, а у источника они заданы явно или не читаются.\n");
    }
    if !caps.hardlinks || caps.remote || source_remote {
        if grouped_links > 0 {
            notes.push_str(&format!("Жёсткие ссылки не сохранены: {} файл(ов) скопированы отдельно.\n", grouped_links));
        }
        if caps.remote || source_remote {
            notes.push_str("Сетевое хранилище: жёсткие ссылки не объединяются, чтобы не связать разные файлы.\n");
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
            cleanup_staging(&mut outcome, plan, staging_id, &created);
            fail(&mut outcome, &journal, "На новом диске недостаточно свободного места. Оригинал не изменён.".into(),
                 format!("Нужно {} байт, свободно {}", total_bytes, free), "failed");
            return outcome;
        }
    }

    // Copy.
    ctx.phase = Phase::Copy;
    ctx.item.clear();
    ctx.bytes_done = 0;
    ctx.files_done = 0;
    ctx.report(true);
    if let Err(error) = copy_tree(plan, &mut entries, &mut ctx, faults, &caps, &mut created) {
        cleanup_staging(&mut outcome, plan, staging_id, &created);
        if ctx.cancelled {
            outcome.cancelled = true;
            outcome.message = "Отменено до изменения исходной папки. Оригинал на месте.".into();
            outcome.detail = error.clone();
            let _ = journal.save("cancelled", &format!("error={}", error));
            return outcome;
        }
        fail(&mut outcome, &journal, "Копирование не завершено. Оригинал не изменён.".into(), error, "failed");
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

    // Verify. Counters are per phase: a mix of copy and verify numbers made the bar jump.
    ctx.phase = Phase::Verify;
    ctx.bytes_done = 0;
    ctx.files_done = 0;
    ctx.report(true);
    if let Err(error) = verify_tree(&plan.staging, &entries, &mut ctx, &caps) {
        if ctx.cancelled {
            cleanup_staging(&mut outcome, plan, staging_id, &created);
            outcome.cancelled = true;
            outcome.message = "Отменено во время сверки. Оригинал на месте.".into();
            let _ = journal.save("cancelled", &format!("error={}", error));
            return outcome;
        }
        cleanup_staging(&mut outcome, plan, staging_id, &created);
        fail(&mut outcome, &journal, "Сверка копии не прошла. Оригинал не изменён.".into(), error, "failed");
        return outcome;
    }
    if faults.verify_mismatch {
        cleanup_staging(&mut outcome, plan, staging_id, &created);
        fail(&mut outcome, &journal, "Сверка копии не прошла. Оригинал не изменён.".into(), "Тестовый сбой сверки".into(), "failed");
        return outcome;
    }
    if let Err(error) = verify_source_unchanged(plan, &entries, &mut ctx) {
        cleanup_staging(&mut outcome, plan, staging_id, &created);
        if ctx.cancelled {
            outcome.cancelled = true;
            outcome.message = "Отменено во время повторной проверки. Оригинал на месте.".into();
            outcome.detail = error.clone();
            let _ = journal.save("cancelled", &format!("error={}", error));
            return outcome;
        }
        fail(&mut outcome, &journal, "Исходная папка изменилась во время переноса. Оригинал не тронут.".into(), error, "failed");
        return outcome;
    }
    // Cancellation is honoured up to this boundary and never after it: once the name starts
    // changing, the operation either finishes or keeps the backup.
    if ctx.cancel_requested() {
        cleanup_staging(&mut outcome, plan, staging_id, &created);
        outcome.cancelled = true;
        outcome.message = "Отменено до переключения. Оригинал на месте.".into();
        let _ = journal.save("cancelled", "cancelled before publish");
        return outcome;
    }
    // The last point where nothing is renamed yet: the record of a verified copy must exist before
    // the folder name starts changing, otherwise a crash would leave an unexplained staging folder.
    if let Err(error) = journal.save("verified", &format!("files={}", total_files)) {
        cleanup_staging(&mut outcome, plan, staging_id, &created);
        fail(&mut outcome, &journal,
             "Журнал восстановления не записан, поэтому перенос остановлен до публикации. Оригинал не изменён.".into(),
             error, "failed");
        return outcome;
    }

    // Publish. The rename must be recorded on disk, otherwise the new name could disappear
    // while the old folder is already gone.
    ctx.phase = Phase::Publish;
    ctx.item = plan.dest_final.clone();
    ctx.report(true);
    if !win::move_path_through(&plan.staging, &plan.dest_final, false) {
        outcome.leftover = plan.staging.clone();
        fail(&mut outcome, &journal, "Не удалось опубликовать копию. Оригинал не изменён, копия сохранена.".into(),
             win::error_text(win::last_error()), "failed");
        return outcome;
    }
    let Some(dest_info) = win::file_info(&plan.dest_final, false) else {
        outcome.leftover = plan.dest_final.clone();
        fail(&mut outcome, &journal, "Копия опубликована, но проверить её не удалось. Оригинал не изменён.".into(),
             String::new(), "published");
        return outcome;
    };
    let dest_id = dest_info.id();
    journal.dest_id = Some(dest_id);
    journal.files = total_files;
    if let Err(error) = journal.save("published", "") {
        // The destination exists but cannot be described in the journal: stop before the rename.
        outcome.leftover = plan.dest_final.clone();
        fail(&mut outcome, &journal, "Копия опубликована, но журнал восстановления не записан. Исходная папка не изменена.".into(),
             error, "published");
        return outcome;
    }

    // Relink. The intention to create a link is recorded before the original is renamed, so a
    // crash at any point leaves a state that matches what a person will actually find on disk.
    ctx.phase = Phase::Link;
    ctx.item = plan.source.clone();
    ctx.report(true);
    if !win::move_path_through(&plan.source, &plan.backup, false) {
        outcome.leftover = plan.dest_final.clone();
        fail(&mut outcome, &journal, "Копия готова, но переименовать оригинал не удалось. Исходная папка не изменена.".into(),
             win::error_text(win::last_error()), "published");
        return outcome;
    }
    if let Err(error) = journal.save("backup", "") {
        // Without a record of the backup the situation cannot be explained later: undo the rename.
        let restored = win::move_path(&plan.backup, &plan.source, false);
        outcome.leftover = if restored { plan.dest_final.clone() } else { plan.backup.clone() };
        fail(&mut outcome, &journal,
             if restored {
                 "Журнал восстановления недоступен, поэтому перенос остановлен. Исходная папка на месте.".into()
             } else {
                 "Журнал восстановления недоступен, и вернуть исходное имя не удалось. Данные целы в двух местах.".into()
             },
             error, if restored { "published" } else { "relink-failed-leftover" });
        return outcome;
    }
    if let Err(error) = journal.save("linking", "") {
        let restored = win::move_path_through(&plan.backup, &plan.source, false);
        outcome.leftover = if restored { plan.dest_final.clone() } else { plan.backup.clone() };
        fail(&mut outcome, &journal,
             if restored {
                 "Журнал восстановления недоступен, поэтому ссылка не создавалась. Исходная папка на месте.".into()
             } else {
                 "Журнал восстановления недоступен. Данные целы в двух местах, ссылка не создавалась.".into()
             },
             error, if restored { "published" } else { "relink-failed-leftover" });
        return outcome;
    }
    let link_result = if faults.link_failure {
        Err(1u32)
    } else {
        win::symlink(&plan.source, &plan.dest_final, true)
    };
    if let Err(code) = link_result {
        let detail = win::error_text(code);
        let (message, leftover) = undo_link(plan, dest_id, true);
        let state = if leftover == plan.backup { "relink-failed-leftover" } else { "relink-failed" };
        outcome.leftover = leftover;
        fail(&mut outcome, &journal, message, detail, state);
        return outcome;
    }
    if !link_still_valid(&plan.source, &plan.dest_final, dest_id) {
        let (message, leftover) = undo_link(plan, dest_id, false);
        let state = if leftover == plan.backup { "relink-failed-leftover" } else { "relink-failed" };
        outcome.leftover = leftover;
        fail(&mut outcome, &journal, message, String::new(), state);
        return outcome;
    }
    if let Err(error) = journal.save("linked", "") {
        // The link works and the backup still exists. Deleting it now would leave no record of
        // what happened if anything goes wrong, so the cleanup waits for the next run.
        outcome.ok = true;
        outcome.leftover = plan.backup.clone();
        outcome.message =
            "Перенос выполнен, ссылка работает. Журнал восстановления не записан, поэтому старый экземпляр сохранён."
                .into();
        outcome.detail = error;
        return outcome;
    }

    // Cleanup.
    ctx.phase = Phase::Cleanup;
    ctx.item = plan.dest_final.clone();
    ctx.report(true);
    if !link_still_valid(&plan.source, &plan.dest_final, dest_id) {
        outcome.leftover = plan.backup.clone();
        fail(&mut outcome, &journal, "Ссылка на старом месте недоступна, старый экземпляр не удалён. Данные сохранены.".into(),
             String::new(), "link-lost");
        return outcome;
    }
    // The copy is checked again inside `delete_backup`, object by object and under a hold that
    // stops writes: a change made after this point cannot cost the original data.
    // Durability: every file was flushed with FlushFileBuffers right after it was written and the
    // rename used MOVEFILE_WRITE_THROUGH, which Windows documents as "does not return until the
    // file is actually moved on the disk". That covers a local volume without elevation.
    // A network share is different: the server decides when its cache reaches the media, so the
    // backup is kept until a person decides otherwise.
    let durability = !faults.force_flush_failure && !caps.remote;
    if durability {
        let _ = win::flush_volume(&plan.dest_final);
    }
    if !durability {
        let reason = if caps.remote {
            "сетевое хранилище не подтверждает запись на диск"
        } else {
            "подтвердить запись на диск не удалось"
        };
        outcome.ok = true;
        outcome.leftover = plan.backup.clone();
        outcome.message = format!("Перенос выполнен, ссылка работает. Старый экземпляр сохранён: {}.", reason);
        outcome.notes.push_str(&format!("Старый экземпляр сохранён: {}.\n", reason));
        let _ = journal.save("cleanup-skipped-durability", reason);
        return outcome;
    }
    if let Some(reason) = protect_from_losses(&entries, &caps) {
        outcome.ok = true;
        outcome.leftover = plan.backup.clone();
        outcome.message = format!(
            "Перенос выполнен, ссылка работает. Старый экземпляр сохранён: {}.",
            reason
        );
        outcome.notes.push_str(&format!("Старый экземпляр сохранён: {}.\n", reason));
        let _ = journal.save("cleanup-skipped-metadata", &reason);
        return outcome;
    }
    if let Some(before_backup_delete) = faults.before_backup_delete {
        before_backup_delete(plan);
    }
    match delete_backup(plan, &entries, dest_id, &caps) {
        Ok(()) => {
            journal.finish("done", "");
            outcome.ok = true;
            outcome.message = "Готово. Папка перенесена, на старом месте — ссылка на новое место.".into();
            outcome
        }
        Err((reason, stopped_at)) => {
            let detail = match &reason {
                CleanupStop::LinkLost(text) | CleanupStop::CopyChanged(text) | CleanupStop::Backup(text) => {
                    text.clone()
                }
            };
            let (ok, message, state) = match &reason {
                CleanupStop::LinkLost(_) => (
                    false,
                    "Ссылка перестала работать. Удаление остановлено, остаток сохранён.".to_string(),
                    "link-lost",
                ),
                CleanupStop::CopyChanged(_) => (
                    true,
                    format!(
                        "Копия изменилась после сверки, поэтому старый экземпляр сохранён. Данные в двух местах: {} и {}.",
                        plan.dest_final, plan.backup
                    ),
                    "cleanup-skipped",
                ),
                CleanupStop::Backup(_) => (
                    true,
                    format!("Перенос выполнен, ссылка работает. Старый экземпляр удалён не полностью: {}", detail),
                    "cleanup-partial",
                ),
            };
            outcome.ok = ok;
            outcome.leftover = stopped_at;
            outcome.message = message;
            outcome.detail = detail;
            let _ = journal.save(state, "");
            outcome
        }
    }
}

/// Removes the link that this run created and puts the original folder back. Returns an honest
/// message and the path that still holds the data, depending on what actually succeeded.
fn undo_link(plan: &Plan, dest_id: win::ObjectId, creation_failed: bool) -> (String, String) {
    // Only a link that points at our own copy is removed: anything else is left untouched.
    let mut link_removed = false;
    let mut link_state = "нет";
    if win::attributes(&plan.source).map(|attrs| attrs & win::FILE_ATTRIBUTE_REPARSE_POINT != 0).unwrap_or(false)
        && link_still_valid(&plan.source, &plan.dest_final, dest_id)
    {
        match win::Guard::open(&plan.source, win::READ_ATTRIBUTES_ACCESS | win::DELETE_ACCESS, false) {
            Ok(mut guard) => {
                if guard.remove().is_ok() {
                    drop(guard);
                    link_removed = !win::path_exists(&plan.source);
                    link_state = if link_removed { "убрана" } else { "осталась" };
                } else {
                    link_state = "осталась";
                }
            }
            Err(_) => link_state = "осталась",
        }
    }
    let restored = if link_removed || !win::path_exists(&plan.source) {
        win::move_path_through(&plan.backup, &plan.source, false)
    } else {
        false
    };
    if restored {
        let message = if creation_failed {
            "Ссылку создать не удалось. Исходная папка восстановлена, проверенная копия осталась на новом месте.".to_string()
        } else {
            "Ссылка не прошла проверку и удалена. Исходная папка восстановлена, проверенная копия осталась на новом месте.".to_string()
        };
        return (message, plan.dest_final.clone());
    }
    let message = format!(
        "Перенос остановлен: ссылка {}, исходное имя восстановить не удалось. Данные целы: копия {}, резерв {}.",
        link_state, plan.dest_final, plan.backup
    );
    (message, plan.backup.clone())
}

/// Decides whether the old folder may be deleted when the destination cannot hold every property
/// of the source. Data-bearing losses are refused much earlier; this covers metadata only.
fn protect_from_losses(entries: &[Entry], caps: &Caps) -> Option<String> {
    if !caps.acl && entries.iter().any(|entry| entry.dacl_explicit) {
        return Some("на новом месте нельзя сохранить права доступа, а у источника они заданы явно или не читаются".to_string());
    }
    if !caps.hardlinks && entries.iter().any(|entry| entry.hardlink_primary.is_some()) {
        return Some("жёсткие ссылки на новом месте не поддерживаются".to_string());
    }
    None
}

/// Journals that describe a transfer which is not finished or left data behind: the link may be
/// missing, or the old folder may still occupy space. Refusals that leave the source in place
/// (`failed`, `cancelled`) stay on disk for diagnosis and are not reported at startup, because the
/// user already saw their result and nothing was moved.
const ATTENTION_STATES: [&str; 13] = [
    "start",
    "copying",
    "verified",
    "published",
    "backup",
    "linking",
    "linked",
    "cleanup-partial",
    "cleanup-skipped",
    "cleanup-skipped-durability",
    "cleanup-skipped-metadata",
    "link-lost",
    "relink-failed-leftover",
];

/// What the GUI needs to tell a person about one interrupted transfer.
#[derive(Clone, Default)]
pub struct JournalSummary {
    pub path: std::path::PathBuf,
    pub state: String,
    pub source: String,
    pub dest: String,
    pub backup: String,
}

impl JournalSummary {
    /// Short Russian description of the recorded state, for people rather than for logs.
    pub fn state_text(&self) -> &'static str {
        match self.state.as_str() {
            "start" | "copying" | "verified" => "перенос не завершён",
            "published" | "backup" => "копия готова, ссылка не создана",
            "linking" => "создавалась ссылка, проверьте папку",
            "linked" => "ссылка создана, резерв мог остаться",
            "cleanup-partial" => "резерв удалён не полностью",
            "cleanup-skipped" | "cleanup-skipped-durability" | "cleanup-skipped-metadata" => {
                "резерв сохранён намеренно"
            }
            "link-lost" => "ссылка перестала работать, резерв сохранён",
            "relink-failed-leftover" => "исходное имя не вернулось, данные в двух местах",
            "unreadable" => "запись журнала не читается",
            _ => "состояние неизвестно",
        }
    }
}

fn journal_field<'a>(text: &'a str, key: &str) -> &'a str {
    text.lines()
        .find_map(|line| line.strip_prefix(key).and_then(|rest| rest.strip_prefix('=')))
        .map(|value| value.trim())
        .unwrap_or("")
}

const JOURNAL_READ_LIMIT: u64 = 64 * 1024;

fn read_journal(path: &std::path::Path) -> Option<String> {
    // A journal is a small regular file created by this program: links and oversized files are
    // skipped instead of being followed.
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() || meta.len() > JOURNAL_READ_LIMIT {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    Some(String::from_utf8_lossy(&bytes).to_string())
}

pub fn unfinished_journals() -> Vec<JournalSummary> {
    let Some(base) = journal_root(false) else {
        // No folder yet means no transfer has ever run here.
        return Vec::new();
    };
    let read_dir = match fs::read_dir(&base) {
        Ok(value) => value,
        Err(_) => {
            // The folder exists but cannot be listed: saying "nothing pending" would be a lie.
            return vec![JournalSummary {
                path: base,
                state: "unreadable".to_string(),
                ..Default::default()
            }];
        }
    };
    let mut result = Vec::new();
    {
        for item in read_dir.flatten() {
            let name = item.file_name().to_string_lossy().to_string();
            if !name.starts_with("journal-") || !name.ends_with(".txt") {
                continue;
            }
            let Some(text) = read_journal(&item.path()) else {
                // The name says "journal" but the content cannot be read: say so instead of
                // pretending there is nothing to see.
                result.push(JournalSummary {
                    path: item.path(),
                    state: "unreadable".to_string(),
                    ..Default::default()
                });
                continue;
            };
            let state = journal_field(&text, "state");
            // An empty state means the record was cut short, so it needs attention too.
            if !state.is_empty() && !ATTENTION_STATES.contains(&state) {
                continue;
            }
            result.push(JournalSummary {
                path: item.path(),
                state: if state.is_empty() { "unreadable".to_string() } else { state.to_string() },
                source: unescape_value(journal_field(&text, "source")),
                dest: unescape_value(journal_field(&text, "dest")),
                backup: unescape_value(journal_field(&text, "backup")),
            });
        }
    }
    result.sort_by(|left, right| left.path.cmp(&right.path));
    result
}
