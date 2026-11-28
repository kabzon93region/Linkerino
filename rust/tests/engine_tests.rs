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

/// Keeps test journals out of the real %LOCALAPPDATA%\Linkerino folder.
fn init_journals() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let dir = std::env::temp_dir().join(format!("linkerino-rs-journals-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        std::env::set_var("LINKERINO_JOURNAL_DIR", &dir);
    });
}

fn temp_root() -> PathBuf {
    use std::sync::atomic::AtomicU64;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    init_journals();
    let base = std::env::temp_dir();
    // Process id alone repeats for every test; the counter keeps roots unique even when the
    // tests run in parallel (the clock alone can return the same tick for two threads).
    let slot = COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = format!("linkerino-rs-{}-{}-{}", std::process::id(), slot, rand_suffix());
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
        let relevant = journal.source.contains(&root_text)
            || journal.dest.contains(&root_text)
            || journal.backup.contains(&root_text);
        if relevant {
            let _ = fs::remove_file(&journal.path);
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
fn copy_changed_after_final_verification_keeps_the_backup() {
    init_journals();
    let root = temp_root();
    require_symlinks(&root);
    let source = root.join("src").join("Data");
    let dest_parent = root.join("dest");
    let stream_path = |dir: &Path| {
        PathBuf::from(format!("{}:test-stream:$DATA", dir.join("file.txt").display()))
    };
    write(&source.join("file.txt"), b"payload");
    write(&stream_path(&source), b"original stream");
    write(&source.join("nested").join("more.txt"), b"more payload");
    fs::create_dir_all(&dest_parent).unwrap();
    let plan = engine::build_plan(&source.to_string_lossy(), &dest_parent.to_string_lossy());
    assert!(plan.valid, "{}", plan.error);
    let faults = Faults {
        before_backup_delete: Some(|plan| {
            let file = Path::new(&plan.dest_final).join("file.txt");
            assert_eq!(read(&file), b"payload");
            fs::write(file, b"changed").expect("change the verified copy");
        }),
        ..Default::default()
    };
    let outcome = engine::execute(&plan, None, &faults);
    let dest = Path::new(&plan.dest_final);
    let backup = Path::new(&plan.backup);
    let link_valid = link_points_to(&source, dest);
    let copy_data = fs::read(dest.join("file.txt"));
    let backup_root = backup.is_dir();
    let backup_data = fs::read(backup.join("file.txt"));
    let backup_nested = fs::read(backup.join("nested").join("more.txt"));
    let backup_stream = fs::read(stream_path(backup));
    let journal_state = journal_state_for(Path::new(&plan.source));
    cleanup(&root);

    assert!(link_valid, "expected the published copy: {}", outcome.message);
    assert_eq!(copy_data.unwrap(), b"changed", "the test action did not run");
    // The whole backup is kept, not just the object that changed: nothing was deleted before the
    // copy was checked again.
    assert!(backup_root, "the backup folder must stay: {} (leftover: {})", outcome.message, outcome.leftover);
    assert_eq!(
        backup_data.as_deref().ok(),
        Some(b"payload".as_slice()),
        "original file must survive the change to the verified copy: {} / {} (leftover: {})",
        outcome.message,
        outcome.detail,
        outcome.leftover
    );
    assert_eq!(
        backup_nested.as_deref().ok(),
        Some(b"more payload".as_slice()),
        "the untouched part of the backup must stay as well: {}",
        outcome.message
    );
    assert_eq!(backup_stream.unwrap(), b"original stream");
    assert!(outcome.ok, "the transfer itself is complete: {}", outcome.message);
    assert!(outcome.message.contains("двух местах"), "{}", outcome.message);
    assert_eq!(outcome.leftover, plan.backup);
    assert_eq!(journal_state.as_deref(), Some("cleanup-skipped"), "{:?}", outcome.detail);
}

/// Reads the state line of the journal that belongs to one transfer.
fn journal_state_for(source: &Path) -> Option<String> {
    let dir = std::env::var("LINKERINO_JOURNAL_DIR").ok()?;
    let escaped = source.to_string_lossy().replace('\\', "\\\\");
    for item in fs::read_dir(dir).ok()?.flatten() {
        let Ok(text) = fs::read_to_string(item.path()) else { continue };
        if !text.contains(&escaped) {
            continue;
        }
        return text
            .lines()
            .find_map(|line| line.strip_prefix("state=").map(|value| value.trim().to_string()));
    }
    None
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
    // A foreign object appeared in the temporary folder: cleanup must keep it instead of deleting
    // something this run did not create, and the path must stay visible as the leftover.
    assert_eq!(outcome.leftover, plan.staging);
    assert!(win::path_exists(&plan.staging), "the foreign object must not be deleted");
    assert!(win::path_exists(&win::join(&plan.staging, "linkerino-tamper-extra.tmp")));
    assert!(!win::path_exists(&plan.dest_final));
    remove_tree(Path::new(&plan.staging));
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
fn directory_with_large_index_moves() {
    let root = temp_root();
    require_symlinks(&root);
    let source = root.join("src").join("Data");
    let dest_parent = root.join("dest");
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(&dest_parent).unwrap();
    // A directory index gets a non-zero size once it grows: it must not look like a source change.
    let mut dir_size = 0;
    for index in 0..600 {
        write(&source.join(format!("entry-{:04}.txt", index)), b"x");
        if index % 50 == 49 {
            dir_size = win::file_info(&source.to_string_lossy(), false).map(|info| info.size).unwrap_or(0);
            if dir_size != 0 {
                break;
            }
        }
    }
    assert!(dir_size != 0, "directory size stayed zero, the regression would not be caught");
    let plan = engine::build_plan(&source.to_string_lossy(), &dest_parent.to_string_lossy());
    assert!(plan.valid, "{}", plan.error);
    let outcome = engine::execute(&plan, None, &Faults::default());
    assert!(outcome.ok, "{} / {}", outcome.message, outcome.detail);
    assert!(link_points_to(&source, Path::new(&plan.dest_final)));
    assert!(read(&source.join("entry-0000.txt")) == b"x");
    cleanup(&root);
}

#[test]
fn only_interrupted_journals_need_attention() {
    init_journals();
    let dir = PathBuf::from(std::env::var("LINKERINO_JOURNAL_DIR").unwrap());
    let pending = dir.join("journal-test-pending.txt");
    let finished = dir.join("journal-test-finished.txt");
    let truncated = dir.join("journal-test-truncated.txt");
    fs::write(&pending, "state=copying\nsource=D:\\a\ndest=D:\\b\nstaging=D:\\s\nbackup=D:\\k\n\n").unwrap();
    fs::write(&finished, "state=failed\nsource=D:\\a\ndest=D:\\b\nstaging=D:\\s\nbackup=D:\\k\nerror=x\n").unwrap();
    fs::write(&truncated, "").unwrap();
    let journals = engine::unfinished_journals();
    let has_pending = journals.iter().any(|journal| journal.path == pending);
    let has_finished = journals.iter().any(|journal| journal.path == finished);
    let has_truncated = journals.iter().any(|journal| journal.path == truncated);
    let _ = fs::remove_file(&pending);
    let _ = fs::remove_file(&finished);
    let _ = fs::remove_file(&truncated);
    assert!(has_pending, "journal in state=copying must be reported");
    assert!(!has_finished, "finished journal must not be reported");
    assert!(has_truncated, "a journal without a state line must be reported");
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
#[test]
fn named_streams_are_read_exactly() {
    let root = temp_root();
    let file = root.join("probe.bin");
    write(&file, b"x");
    fs::write(format!("{}:custom:$DATA", file.to_string_lossy()), b"stream-data").unwrap();
    let names: Vec<(String, u64)> = win::streams(&file.to_string_lossy())
        .expect("streams")
        .into_iter()
        .map(|stream| (stream.name, stream.size))
        .collect();
    assert_eq!(names, vec![("custom".to_string(), 11)]);
    cleanup(&root);
}
#[test]
fn plan_is_revalidated_before_any_change() {
    let root = temp_root();
    require_symlinks(&root);
    let source = root.join("src").join("Data");
    let dest_parent = root.join("dest");
    write(&source.join("keep.txt"), b"original");
    fs::create_dir_all(&dest_parent).unwrap();
    let plan = engine::build_plan(&source.to_string_lossy(), &dest_parent.to_string_lossy());
    assert!(plan.valid, "{}", plan.error);
    // Replace the confirmed folder with another one at the same path.
    fs::rename(&source, root.join("src").join("Data-old")).unwrap();
    write(&source.join("other.txt"), b"other");
    let outcome = engine::execute(&plan, None, &Faults::default());
    assert!(!outcome.ok, "a replaced source must stop the transfer");
    assert!(outcome.message.contains("изменились"), "unexpected message: {}", outcome.message);
    assert!(!win::path_exists(&plan.dest_final), "nothing must be published");
    assert!(!win::path_exists(&plan.staging), "staging must not be left behind");
    assert!(source.join("other.txt").exists(), "the current folder must stay untouched");
    cleanup(&root);
}

#[test]
fn journal_inside_source_is_rejected_before_writing() {
    let root = temp_root();
    require_symlinks(&root);
    let (source, dest_parent, plan) = prepare(&root);
    let journal_dir = source.join("journals");
    // Scope the journal override to this child so parallel tests keep their own journal location.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_Linkerino"))
        .env("LINKERINO_JOURNAL_DIR", &journal_dir)
        .args(["--transfer", "--json", "--quiet"])
        .arg(&source)
        .arg(&dest_parent)
        .output()
        .expect("run Linkerino with a journal directory inside the source");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let source_id = win::object_id(&plan.source, true);
    let source_data = fs::read(source.join("file.txt"));
    let journal_not_created = matches!(
        fs::symlink_metadata(&journal_dir),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    );
    let dest_empty = fs::read_dir(&dest_parent).unwrap().next().is_none();
    cleanup(&root);

    assert_eq!(source_id, Some(plan.source_id), "the source folder was replaced: {stdout}");
    assert_eq!(source_data.unwrap(), b"payload");
    assert!(journal_not_created, "the source tree must not get a journal directory: {stdout}");
    assert!(dest_empty, "the destination must stay empty: {stdout}");
    assert_eq!(output.status.code(), Some(1), "expected a refusal: {stdout}");
    assert!(stdout.to_lowercase().contains("журнал"), "expected a journal diagnostic: {stdout}");
}

#[test]
fn journal_beside_the_source_does_not_block_the_move() {
    let root = temp_root();
    require_symlinks(&root);
    let (source, dest_parent, _plan) = prepare(&root);
    // A folder next to the source is not inside it: the refusal must not appear here.
    let journal_dir = root.join("journals");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_Linkerino"))
        .env("LINKERINO_JOURNAL_DIR", &journal_dir)
        .args(["--transfer", "--json", "--quiet"])
        .arg(&source)
        .arg(&dest_parent)
        .output()
        .expect("run Linkerino with the journal folder beside the source");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let linked = win::is_reparse(&source.to_string_lossy());
    let copied = dest_parent.join("Data").join("file.txt");
    let copied_data = fs::read(&copied);
    cleanup(&root);

    assert_eq!(output.status.code(), Some(0), "a journal folder beside the source must not block: {stdout}");
    assert!(linked, "the source must become a link: {stdout}");
    assert_eq!(copied_data.unwrap(), b"payload");
}

#[test]
fn journal_inside_the_future_copy_is_refused_before_writing() {
    let root = temp_root();
    require_symlinks(&root);
    let (source, dest_parent, _plan) = prepare(&root);
    let journal_dir = dest_parent.join("Data").join("journals");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_Linkerino"))
        .env("LINKERINO_JOURNAL_DIR", &journal_dir)
        .args(["--transfer", "--json", "--quiet"])
        .arg(&source)
        .arg(&dest_parent)
        .output()
        .expect("run Linkerino with a journal folder inside the future copy");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let linked = win::is_reparse(&source.to_string_lossy());
    let journal_created = win::path_exists(&journal_dir.to_string_lossy());
    let copy_created = win::path_exists(&dest_parent.join("Data").to_string_lossy());
    let source_data = fs::read(source.join("file.txt"));
    cleanup(&root);

    assert_eq!(output.status.code(), Some(1), "expected a refusal: {stdout}");
    assert!(stdout.to_lowercase().contains("журнал"), "expected a journal diagnostic: {stdout}");
    assert!(!linked, "the source must stay a real folder: {stdout}");
    assert!(!journal_created, "the journal folder must not be created: {stdout}");
    assert!(!copy_created, "the copy must not be created: {stdout}");
    assert_eq!(source_data.unwrap(), b"payload");
}

#[test]
fn interrupted_transfer_keeps_a_journal() {
    init_journals();
    let root = temp_root();
    require_symlinks(&root);
    let source = root.join("src").join("Data");
    let dest_parent = root.join("dest");
    write(&source.join("file.txt"), b"payload");
    fs::create_dir_all(&dest_parent).unwrap();
    let plan = engine::build_plan(&source.to_string_lossy(), &dest_parent.to_string_lossy());
    assert!(plan.valid, "{}", plan.error);
    let mut faults = Faults::default();
    faults.link_failure = true;
    let outcome = engine::execute(&plan, None, &faults);
    assert!(!outcome.ok);
    let journals = engine::unfinished_journals();
    let found = journals.iter().find(|journal| journal.source.contains(&root.to_string_lossy().to_string()));
    // relink-failed is a finished state, so it must be kept on disk but not reported as pending.
    let dir = PathBuf::from(std::env::var("LINKERINO_JOURNAL_DIR").unwrap());
    let files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|item| item.path())
        .filter(|path| {
            fs::read_to_string(path)
                .map(|text| text.contains("state=relink-failed") && text.contains(&plan.source.replace('\\', "\\\\")))
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(files.len(), 1, "the journal of the failed link must describe the situation");
    assert!(found.is_none(), "a finished state must not be reported as pending");
    for file in files {
        let _ = fs::remove_file(file);
    }
    cleanup(&root);
}

#[test]
fn successful_transfer_leaves_no_journal() {
    init_journals();
    let root = temp_root();
    require_symlinks(&root);
    let source = root.join("src").join("Data");
    let dest_parent = root.join("dest");
    write(&source.join("file.txt"), b"payload");
    fs::create_dir_all(&dest_parent).unwrap();
    let plan = engine::build_plan(&source.to_string_lossy(), &dest_parent.to_string_lossy());
    assert!(plan.valid, "{}", plan.error);
    let outcome = engine::execute(&plan, None, &Faults::default());
    assert!(outcome.ok, "{} / {}", outcome.message, outcome.detail);
    let dir = PathBuf::from(std::env::var("LINKERINO_JOURNAL_DIR").unwrap());
    let leftovers: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|item| item.path())
        .filter(|path| {
            fs::read_to_string(path).map(|text| text.contains(&plan.source.replace('\\', "\\\\"))).unwrap_or(false)
        })
        .collect();
    assert!(leftovers.is_empty(), "a finished transfer must not leave a journal: {:?}", leftovers);
    cleanup(&root);
}

#[test]
fn unreadable_and_kept_backup_journals_are_reported() {
    init_journals();
    let dir = PathBuf::from(std::env::var("LINKERINO_JOURNAL_DIR").unwrap());
    let broken = dir.join("journal-test-broken.txt");
    let kept = dir.join("journal-test-kept.txt");
    let lost = dir.join("journal-test-lost.txt");
    let orphan = dir.join("journal-test-orphan.txt");
    fs::write(&broken, vec![0u8; 100]).unwrap();
    fs::write(
        &kept,
        "version=3\nstate=cleanup-skipped-durability\nsource=D:\\a\nbackup=D:\\k\n",
    )
    .unwrap();
    fs::write(&lost, "version=3\nstate=link-lost\nsource=D:\\a\nbackup=D:\\k\n").unwrap();
    fs::write(&orphan, "version=3\nstate=relink-failed-leftover\nsource=D:\\b\nbackup=D:\\m\n").unwrap();
    let journals = engine::unfinished_journals();
    let broken_entry = journals.iter().find(|journal| journal.path == broken);
    let kept_entry = journals.iter().find(|journal| journal.path == kept);
    let lost_entry = journals.iter().find(|journal| journal.path == lost);
    let orphan_entry = journals.iter().find(|journal| journal.path == orphan);
    assert_eq!(broken_entry.map(|journal| journal.state.as_str()), Some("unreadable"));
    assert_eq!(
        broken_entry.map(|journal| journal.state_text()),
        Some("запись журнала не читается")
    );
    assert_eq!(kept_entry.map(|journal| journal.state.as_str()), Some("cleanup-skipped-durability"));
    assert_eq!(kept_entry.map(|journal| journal.state_text()), Some("резерв сохранён намеренно"));
    assert_eq!(lost_entry.map(|journal| journal.state.as_str()), Some("link-lost"));
    assert_eq!(
        lost_entry.map(|journal| journal.state_text()),
        Some("ссылка перестала работать, резерв сохранён")
    );
    assert_eq!(orphan_entry.map(|journal| journal.state.as_str()), Some("relink-failed-leftover"));
    assert_eq!(
        orphan_entry.map(|journal| journal.state_text()),
        Some("исходное имя не вернулось, данные в двух местах")
    );
    for path in [&broken, &kept, &lost, &orphan] {
        let _ = fs::remove_file(path);
    }
}

#[test]
fn failure_after_create_still_cleans_the_staging() {
    let root = temp_root();
    require_symlinks(&root);
    let (source, _dest_parent, plan) = prepare(&root);
    let faults = Faults { copy_failure_after_create: true, ..Default::default() };
    let outcome = engine::execute(&plan, None, &faults);
    assert!(!outcome.ok);
    assert!(outcome.detail.contains("после создания"), "{}", outcome.detail);
    // The file was created before the failure, so the object must already be registered: nothing
    // of the temporary folder may stay behind.
    assert!(!win::path_exists(&plan.staging), "staging must be removed (leftover: {})", outcome.leftover);
    assert!(outcome.leftover.is_empty(), "unexpected leftover: {}", outcome.leftover);
    assert!(source.join("file.txt").exists());
    cleanup(&root);
}

#[test]
fn junction_inside_tree_is_recreated() {
    let root = temp_root();
    require_symlinks(&root);
    let source = root.join("src").join("Data");
    let target = root.join("target-outside");
    let dest_parent = root.join("dest");
    write(&target.join("file.txt"), b"junction payload");
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(&dest_parent).unwrap();
    let link = source.join("mount");
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J", &link.to_string_lossy(), &target.to_string_lossy()])
        .status()
        .expect("mklink");
    assert!(status.success(), "could not create a junction for the test");
    let plan = engine::build_plan(&source.to_string_lossy(), &dest_parent.to_string_lossy());
    assert!(plan.valid, "{}", plan.error);
    let outcome = engine::execute(&plan, None, &Faults::default());
    assert!(outcome.ok, "{} / {}", outcome.message, outcome.detail);
    let copied = Path::new(&plan.dest_final).join("mount");
    assert!(win::is_reparse(&copied.to_string_lossy()), "junction was not recreated");
    assert!(read(&copied.join("file.txt")) == b"junction payload");
    cleanup(&root);
}

#[test]
fn relative_link_inside_tree_points_at_the_new_place() {
    let root = temp_root();
    require_symlinks(&root);
    let source = root.join("src").join("Data");
    let dest_parent = root.join("dest");
    write(&source.join("data").join("file.txt"), b"relative payload");
    fs::create_dir_all(&dest_parent).unwrap();
    let link = source.join("inner");
    // A relative target: it must be recreated as an absolute path to the new location.
    win::symlink(&link.to_string_lossy(), "data", true).expect("symlink");
    let plan = engine::build_plan(&source.to_string_lossy(), &dest_parent.to_string_lossy());
    assert!(plan.valid, "{}", plan.error);
    let outcome = engine::execute(&plan, None, &Faults::default());
    assert!(outcome.ok, "{} / {}", outcome.message, outcome.detail);
    let copied = Path::new(&plan.dest_final).join("inner");
    assert!(win::is_reparse(&copied.to_string_lossy()));
    let resolved = win::canonical(&copied.to_string_lossy()).unwrap_or_default();
    let expected = win::canonical(&win::join(&plan.dest_final, "data")).unwrap_or_default();
    assert!(resolved.eq_ignore_ascii_case(&expected), "resolved to {}", resolved);
    assert!(read(&copied.join("file.txt")) == b"relative payload");
    cleanup(&root);
}

#[test]
fn junction_inside_source_points_at_the_new_place() {
    let root = temp_root();
    require_symlinks(&root);
    let source = root.join("src").join("Data");
    let dest_parent = root.join("dest");
    write(&source.join("real").join("file.txt"), b"inner junction");
    fs::create_dir_all(&dest_parent).unwrap();
    let link = source.join("mount");
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J", &link.to_string_lossy(), &source.join("real").to_string_lossy()])
        .status()
        .expect("mklink");
    assert!(status.success(), "could not create a junction for the test");
    let plan = engine::build_plan(&source.to_string_lossy(), &dest_parent.to_string_lossy());
    assert!(plan.valid, "{}", plan.error);
    let outcome = engine::execute(&plan, None, &Faults::default());
    assert!(outcome.ok, "{} / {}", outcome.message, outcome.detail);
    let copied = Path::new(&plan.dest_final).join("mount");
    assert!(win::is_reparse(&copied.to_string_lossy()));
    // The junction must be rewritten to the new location, not copied with the old target text.
    let actual = win::read_reparse(&copied.to_string_lossy()).expect("reparse");
    let expected = win::join(&plan.dest_final, "real");
    assert!(
        win::normalize_target(&actual.substitute).eq_ignore_ascii_case(&expected),
        "junction still points at {}",
        actual.substitute
    );
    assert!(read(&copied.join("file.txt")) == b"inner junction");
    cleanup(&root);
}
