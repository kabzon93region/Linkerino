use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use linkerino::engine::{self, Faults, Sink};
use linkerino::win;

struct CancelSink(Arc<AtomicBool>);
impl Sink for CancelSink {
    fn progress(&self, _progress: &engine::Progress) {}
    fn cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

fn temp_root() -> PathBuf {
    let base = std::env::temp_dir();
    let name = format!("linkerino-rs-{}", std::process::id() as u64 * 1000 + rand_suffix());
    let path = base.join(name);
    fs::create_dir_all(&path).unwrap();
    path
}

fn rand_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos() as u64
}

fn write(path: &Path, data: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, data).unwrap();
}

fn read(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap()
}

fn remove_tree(path: &Path) {
    if !path.exists() {
        return;
    }
    if win::is_reparse(&path.to_string_lossy()) {
        let _ = win::delete_dir(&path.to_string_lossy());
        let _ = win::delete_file(&path.to_string_lossy());
        return;
    }
    if path.is_dir() {
        for item in fs::read_dir(path).unwrap().flatten() {
            remove_tree(&item.path());
        }
        let _ = fs::remove_dir(path);
    } else {
        let _ = fs::remove_file(path);
    }
}

fn can_create_symlinks(probe_dir: &Path) -> bool {
    let link = probe_dir.join("linkerino-probe-link");
    let target = probe_dir.to_string_lossy().to_string();
    match win::symlink(&link.to_string_lossy(), &target, true) {
        Ok(()) => {
            let _ = win::delete_dir(&link.to_string_lossy());
            true
        }
        Err(_) => false,
    }
}

fn require_symlinks(probe_dir: &Path) {
    assert!(
        can_create_symlinks(probe_dir),
        "тесты требуют прав администратора: не удалось создать символьную ссылку"
    );
}

fn cleanup(root: &Path) {
    remove_tree(root);
    let root_text = root.to_string_lossy().to_string();
    for journal in engine::unfinished_journals() {
        if let Ok(text) = fs::read_to_string(&journal) {
            if text.contains(&root_text) {
                let _ = fs::remove_file(&journal);
            }
        }
    }
}

fn link_points_to(link: &Path, target: &Path) -> bool {
    let link_text = link.to_string_lossy().to_string();
    if !win::is_reparse(&link_text) {
        return false;
    }
    let resolved = win::canonical(&link_text).unwrap_or_default();
    let expected = win::canonical(&target.to_string_lossy()).unwrap_or_default();
    !resolved.is_empty() && !expected.is_empty() && resolved.eq_ignore_ascii_case(&expected)
}

#[test]
fn basic_move_keeps_data_and_creates_link() {
    let root = temp_root();
    require_symlinks(&root);
    let source = root.join("src").join("Data");
    let dest_parent = root.join("dest");
    write(&source.join("hello.txt"), b"hello linkerino");
    write(&source.join("nested").join("file with space.txt"), b"unicode data");
    write(&source.join("empty.bin"), b"");
    fs::create_dir_all(source.join("empty-dir")).unwrap();
    let stream = format!("{}:Zone.identifier:$DATA", source.join("hello.txt").to_string_lossy());
    write(Path::new(&stream), b"[ZoneTransfer]\r\nZoneId=3\r\n");
    fs::create_dir_all(&dest_parent).unwrap();

    let plan = engine::build_plan(&source.to_string_lossy(), &dest_parent.to_string_lossy());
    assert!(plan.valid, "plan invalid: {}", plan.error);
    assert_eq!(win::leaf(&plan.dest_final), "Data");
    let outcome = engine::execute(&plan, None, &Faults::default());
    assert!(outcome.ok, "execute failed: {} / {}", outcome.message, outcome.detail);
    assert!(link_points_to(&source, Path::new(&plan.dest_final)), "source is not a link to the copy");
    assert!(read(&dest_parent.join("Data").join("hello.txt")) == b"hello linkerino");
    assert!(read(&source.join("hello.txt")) == b"hello linkerino");
    let copied_stream = format!("{}:Zone.identifier:$DATA", dest_parent.join("Data").join("hello.txt").to_string_lossy());
    assert!(read(Path::new(&copied_stream)).starts_with(b"[ZoneTransfer]"));
    assert!(!win::path_exists(&plan.staging));
    assert!(outcome.message.contains("Готово"), "unexpected message: {}", outcome.message);
    assert!(
        !win::path_exists(&plan.backup),
        "backup must be gone after a successful transfer (leftover: {})",
        outcome.leftover
    );
    assert!(outcome.leftover.is_empty(), "unexpected leftover: {}", outcome.leftover);
    cleanup(&root);
}

#[test]
fn destination_collision_is_rejected() {
    let root = temp_root();
    let source = root.join("src").join("Data");
    let dest_parent = root.join("dest");
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(dest_parent.join("Data")).unwrap();
    let plan = engine::build_plan(&source.to_string_lossy(), &dest_parent.to_string_lossy());
    assert!(!plan.valid);
    assert!(plan.error.contains("уже есть объект"), "unexpected: {}", plan.error);
    cleanup(&root);
}

#[test]
fn symlink_inside_tree_is_recreated() {
    let root = temp_root();
    require_symlinks(&root);
    let source = root.join("src").join("Data");
    let dest_parent = root.join("dest");
    write(&source.join("data").join("file.txt"), b"linked payload");
    fs::create_dir_all(&dest_parent).unwrap();
    let link = source.join("inner");
    win::symlink(&link.to_string_lossy(), &source.join("data").to_string_lossy(), true).unwrap();

    let plan = engine::build_plan(&source.to_string_lossy(), &dest_parent.to_string_lossy());
    assert!(plan.valid, "{}", plan.error);
    let outcome = engine::execute(&plan, None, &Faults::default());
    assert!(outcome.ok, "{} / {}", outcome.message, outcome.detail);
    let copied = Path::new(&plan.dest_final).join("inner");
    assert!(win::is_reparse(&copied.to_string_lossy()));
    assert!(read(&copied.join("file.txt")) == b"linked payload");
    cleanup(&root);
}

#[test]
fn hard_links_are_preserved() {
    let root = temp_root();
    require_symlinks(&root);
    let source = root.join("src").join("Data");
    let dest_parent = root.join("dest");
    write(&source.join("one.txt"), b"hard link payload");
    fs::create_dir_all(&dest_parent).unwrap();
    assert!(win::hard_link(
        &source.join("one.txt").to_string_lossy(),
        &source.join("two.txt").to_string_lossy()
    ));
    let plan = engine::build_plan(&source.to_string_lossy(), &dest_parent.to_string_lossy());
    assert!(plan.valid, "{}", plan.error);
    let outcome = engine::execute(&plan, None, &Faults::default());
    assert!(outcome.ok, "{} / {}", outcome.message, outcome.detail);
    let first = win::file_info(&Path::new(&plan.dest_final).join("one.txt").to_string_lossy(), false).unwrap();
    let second = win::file_info(&Path::new(&plan.dest_final).join("two.txt").to_string_lossy(), false).unwrap();
    assert_eq!(first.index, second.index);
    assert_eq!(first.links, 2);
    cleanup(&root);
}

#[test]
fn long_paths_are_supported() {
    let root = temp_root();
    require_symlinks(&root);
    let source = root.join("src").join("Data");
    let dest_parent = root.join("dest");
    let mut deep = source.clone();
    for level in 0..12 {
        deep = deep.join(format!("directory-with-long-name-{}", level));
    }
    write(&deep.join("deep-file.txt"), b"deep payload");
    assert!(deep.to_string_lossy().len() > 260);
    fs::create_dir_all(&dest_parent).unwrap();
    let plan = engine::build_plan(&source.to_string_lossy(), &dest_parent.to_string_lossy());
    assert!(plan.valid, "{}", plan.error);
    let outcome = engine::execute(&plan, None, &Faults::default());
    assert!(outcome.ok, "{} / {}", outcome.message, outcome.detail);
    let copied = Path::new(&plan.dest_final).join(deep.strip_prefix(&source).unwrap());
    assert!(read(&copied.join("deep-file.txt")) == b"deep payload");
    cleanup(&root);
}

#[test]
fn directory_streams_are_copied() {
    let root = temp_root();
    require_symlinks(&root);
    let source = root.join("src").join("Data");
    let dest_parent = root.join("dest");
    write(&source.join("a.txt"), b"data");
    fs::create_dir_all(&dest_parent).unwrap();
    let stream = format!("{}:DirStream:$DATA", source.to_string_lossy());
    write(Path::new(&stream), b"dir-stream-payload");
    let plan = engine::build_plan(&source.to_string_lossy(), &dest_parent.to_string_lossy());
    assert!(plan.valid, "{}", plan.error);
    let outcome = engine::execute(&plan, None, &Faults::default());
    assert!(outcome.ok, "{} / {}", outcome.message, outcome.detail);
    let copied = format!("{}:DirStream:$DATA", plan.dest_final);
    assert_eq!(read(Path::new(&copied)), b"dir-stream-payload");
    cleanup(&root);
}

#[test]
fn cancel_keeps_the_original() {
    let root = temp_root();
    require_symlinks(&root);
    let source = root.join("src").join("Data");
    let dest_parent = root.join("dest");
    write(&source.join("big.bin"), vec![b'x'; 4 * 1024 * 1024].as_slice());
    fs::create_dir_all(&dest_parent).unwrap();
    let plan = engine::build_plan(&source.to_string_lossy(), &dest_parent.to_string_lossy());
    assert!(plan.valid, "{}", plan.error);
    let flag = Arc::new(AtomicBool::new(true));
    let sink = CancelSink(flag);
    let outcome = engine::execute(&plan, Some(&sink), &Faults::default());
    assert!(outcome.cancelled, "expected cancellation: {}", outcome.message);
    assert!(source.join("big.bin").exists());
    assert!(!win::path_exists(&plan.staging));
    cleanup(&root);
}

#[test]
fn link_failure_restores_the_source() {
    let root = temp_root();
    require_symlinks(&root);
    let source = root.join("src").join("Data");
    let dest_parent = root.join("dest");
    write(&source.join("file.txt"), b"payload");
    fs::create_dir_all(&dest_parent).unwrap();
    let plan = engine::build_plan(&source.to_string_lossy(), &dest_parent.to_string_lossy());
    assert!(plan.valid, "{}", plan.error);
    let faults = Faults { link_failure: true, ..Default::default() };
    let outcome = engine::execute(&plan, None, &faults);
    assert!(!outcome.ok);
    assert!(!win::is_reparse(&source.to_string_lossy()), "source must stay a real folder");
    assert!(read(&source.join("file.txt")) == b"payload");
    assert!(Path::new(&plan.dest_final).join("file.txt").exists());
    cleanup(&root);
}

#[test]
fn plan_rejects_bad_inputs() {
    let root = temp_root();
    let source = root.join("src").join("Data");
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(source.join("sub")).unwrap();
    let inside = engine::build_plan(&source.to_string_lossy(), &source.join("sub").to_string_lossy());
    assert!(!inside.valid);
    assert!(inside.error.contains("внутри"), "unexpected: {}", inside.error);
    let same = engine::build_plan(&source.to_string_lossy(), &source.to_string_lossy());
    assert!(!same.valid);
    let missing = engine::build_plan(&root.join("missing").to_string_lossy(), &root.to_string_lossy());
    assert!(!missing.valid);
    let empty = engine::build_plan("", &root.to_string_lossy());
    assert!(!empty.valid);
    assert!(!empty.error.is_empty());
    let root_disk = engine::build_plan("C:\\", &root.to_string_lossy());
    assert!(!root_disk.valid, "a drive root must never be moved");
    assert!(root_disk.error.contains("корень"), "unexpected: {}", root_disk.error);
    let quoted = engine::build_plan(&format!("\"{}\"", source.to_string_lossy()), &root.to_string_lossy());
    assert!(quoted.valid, "quoted path rejected: {}", quoted.error);
    cleanup(&root);
}

fn prepare(root: &Path) -> (PathBuf, PathBuf, engine::Plan) {
    let source = root.join("src").join("Data");
    let dest_parent = root.join("dest");
    write(&source.join("file.txt"), b"payload");
    write(&source.join("nested").join("more.txt"), b"more payload");
    fs::create_dir_all(&dest_parent).unwrap();
    let plan = engine::build_plan(&source.to_string_lossy(), &dest_parent.to_string_lossy());
    assert!(plan.valid, "{}", plan.error);
    (source, dest_parent, plan)
}

#[test]
fn low_space_stops_before_copying() {
    let root = temp_root();
    require_symlinks(&root);
    let (source, _dest_parent, plan) = prepare(&root);
    let faults = Faults { low_space: true, ..Default::default() };
    let outcome = engine::execute(&plan, None, &faults);
    assert!(!outcome.ok);
    assert!(outcome.message.contains("недостаточно свободного места"), "{}", outcome.message);
    assert!(read(&source.join("file.txt")) == b"payload");
    assert!(!win::path_exists(&plan.staging));
    assert!(!win::path_exists(&plan.dest_final));
    cleanup(&root);
}

#[test]
fn copy_failure_keeps_original() {
    let root = temp_root();
    require_symlinks(&root);
    let (source, _dest_parent, plan) = prepare(&root);
    let faults = Faults { copy_failure: true, ..Default::default() };
    let outcome = engine::execute(&plan, None, &faults);
    assert!(!outcome.ok);
    assert!(!win::is_reparse(&source.to_string_lossy()));
    assert!(read(&source.join("file.txt")) == b"payload");
    assert!(!win::path_exists(&plan.staging));
    cleanup(&root);
}

#[test]
fn verify_mismatch_keeps_original() {
    let root = temp_root();
    require_symlinks(&root);
    let (source, _dest_parent, plan) = prepare(&root);
    let faults = Faults { verify_mismatch: true, ..Default::default() };
    let outcome = engine::execute(&plan, None, &faults);
    assert!(!outcome.ok);
    assert!(outcome.message.contains("Сверка копии не прошла"), "{}", outcome.message);
    assert!(!win::is_reparse(&source.to_string_lossy()));
    assert!(!win::path_exists(&plan.dest_final));
    assert!(!win::path_exists(&plan.staging));
    cleanup(&root);
}

#[test]
fn flush_failure_keeps_the_backup() {
    let root = temp_root();
    require_symlinks(&root);
    let (source, _dest_parent, plan) = prepare(&root);
    let faults = Faults { force_flush_failure: true, ..Default::default() };
    let outcome = engine::execute(&plan, None, &faults);
    assert!(outcome.ok, "{} / {}", outcome.message, outcome.detail);
    assert!(link_points_to(&source, Path::new(&plan.dest_final)));
    assert_eq!(outcome.leftover, plan.backup);
    assert!(win::path_exists(&plan.backup), "backup must survive a failed volume flush");
    assert!(read(&Path::new(&plan.backup).join("file.txt")) == b"payload");
    cleanup(&root);
}

#[test]
fn extra_object_in_copy_is_rejected() {
    let root = temp_root();
    require_symlinks(&root);
    let (source, _dest_parent, plan) = prepare(&root);
    let faults = Faults { tamper_extra: true, ..Default::default() };
    let outcome = engine::execute(&plan, None, &faults);
    assert!(!outcome.ok);
    assert!(outcome.message.contains("Сверка копии не прошла"), "{}", outcome.message);
    assert!(outcome.detail.contains("лишний объект"), "{}", outcome.detail);
    assert!(!win::is_reparse(&source.to_string_lossy()));
    assert!(!win::path_exists(&plan.staging));
    assert!(!win::path_exists(&plan.dest_final));
    cleanup(&root);
}

#[test]
fn missing_object_in_copy_is_rejected() {
    let root = temp_root();
    require_symlinks(&root);
    let (source, _dest_parent, plan) = prepare(&root);
    let faults = Faults { tamper_missing: true, ..Default::default() };
    let outcome = engine::execute(&plan, None, &faults);
    assert!(!outcome.ok);
    assert!(outcome.message.contains("Сверка копии не прошла"), "{}", outcome.message);
    assert!(outcome.detail.contains("нет объекта"), "{}", outcome.detail);
    assert!(!win::is_reparse(&source.to_string_lossy()));
    assert!(read(&source.join("file.txt")) == b"payload");
    assert!(!win::path_exists(&plan.staging));
    assert!(!win::path_exists(&plan.dest_final));
    cleanup(&root);
}

#[test]
fn unicode_names_survive() {
    let root = temp_root();
    require_symlinks(&root);
    let source = root.join("src").join("Данные");
    let dest_parent = root.join("dest");
    write(&source.join("файл с пробелом.txt"), "привет".as_bytes());
    write(&source.join("папка").join("ёмкость.txt"), "тест".as_bytes());
    fs::create_dir_all(&dest_parent).unwrap();
    let plan = engine::build_plan(&source.to_string_lossy(), &dest_parent.to_string_lossy());
    assert!(plan.valid, "{}", plan.error);
    let outcome = engine::execute(&plan, None, &Faults::default());
    assert!(outcome.ok, "{} / {}", outcome.message, outcome.detail);
    assert!(read(&source.join("файл с пробелом.txt")) == "привет".as_bytes());
    assert!(read(&Path::new(&plan.dest_final).join("папка").join("ёмкость.txt")) == "тест".as_bytes());
    cleanup(&root);
}
