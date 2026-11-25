# Карта кода: Linkerino

Обновлено: 2026-11-25 (версии 1.1 и 2.1.1). Источник истины — код; карта помогает навигации.

## Версия 2.x на Rust

| Файл | Ответственность |
|---|---|
| `rust/Cargo.toml` | Пакет `linkerino` 2.1.1: `[lib]` + бинарник `Linkerino`, `build.rs`, release-профиль `opt-level="z"`, LTO, `panic=abort`, strip |
| `rust/build.rs` | Ресурсы Windows через `winres`: иконка из `assets/linkerino.ico`, `ProductName`, `FileDescription`, версия из `Cargo.toml` (2.1.1) |
| `rust/assets/` | `linkerino.ico` (16–256), `linkerino-256.png` для окна, `linkerino-1024.png` — исходник |
| `.cargo/config.toml` | `+crt-static` для x86_64-pc-windows-msvc: CRT вкомпилирован, Visual C++ Redistributable не нужен |
| `rust/src/lib.rs` | Точка сборки библиотеки: `pub mod engine; pub mod win;` |
| `rust/src/win.rs` | Win32 через `windows-sys`: пути (`\\?\`), канонизация, атрибуты, `MoveFileExW`, `file_info` (`FileId`), жёсткие ссылки, `symlink`, потоки (`FileStreamInfo`), reparse-точки (`read_reparse`, `write_junction`), DACL (`acl_signature`, `apply_acl`, `dacl_protected`), том (`volume_root`, `volume_info`, `free_space`, `flush_volume`), тексты ошибок |
| `rust/src/engine.rs` | `Phase`, `Progress`, `Sink`, `Faults`, `Plan`, `Outcome`; `build_plan`, `execute`, снимок `scan_dir`, группы жёстких ссылок, `probe_caps`/`probe_acl`, `copy_tree`, `verify_tree` + `verify_path_set` (сверка набора путей), `verify_source_unchanged`, журнал, `delete_backup`, `unfinished_journals` |
| `rust/src/main.rs` | Окно egui: карточки путей в одну строку, итоговый путь, прогресс, статус, подтверждение, итог, путь остатка и кнопки (путь и кнопки видны всегда, сообщение итога прокручивается), единая палитра `Palette` и `apply_theme` для светлой и тёмной темы, тумблер темы «солнце/месяц» рядом с названием, окно незавершённых журналов с прокруткой и кнопками «Понятно»/«Открыть папку журналов»; режимы `--transfer`, `--screenshot`, `--demo`, `--demo-result`, `--demo-journals`, `--theme`; системный шрифт Segoe UI; 2 юнит-теста разбора темы |
| `rust/tests/engine_tests.rs` | 18 интеграционных тестов движка на временных каталогах |
| `scripts/smoke-rust.ps1` | Перенос без интерфейса, проверка ссылки, окно, три снимка окна (светлая, итог, тёмная) |
| `scripts/make-icon.py` | Dev-скрипт перерисовки иконки (Pillow): ICO 16–256 и PNG; в поставку не входит |

### Контракты Rust

- `build_plan(source_input, dest_input) -> Plan` — только читает; ошибки текстом в `plan.error`; проверяет корень диска, коллизию, вложенность, системные каталоги, профиль, NTFS/ReFS на источнике.
- `execute(plan, sink: Option<&dyn Sink>, faults: &Faults) -> Outcome` — рабочий поток; `leftover` — где остались данные, `notes` — что не перенесено, `needs_elevation` — не хватило прав (1314).
- `Sink::progress` вызывается не чаще 100 мс, кроме принудительных вызовов на границах фаз; `Sink::cancelled` опрашивается только до `Publish`.
- `Faults` есть только у Rust-тестов: `copy_failure`, `verify_mismatch`, `link_failure`, `low_space`, `force_flush_failure`, `tamper_extra`, `tamper_missing` (две последние подменяют копию, чтобы проверить сверку набора путей).
- Журнал: папка `%LOCALAPPDATA%\Linkerino` (переопределяется `LINKERINO_JOURNAL_DIR`, тесты пишут во временную папку); состояния `start`, `copying`, `verified`, `published`, `backup`, `linked`, `cleanup-partial`, `cleanup-skipped`, `cleanup-skipped-durability`, `link-lost`, `failed`, `cancelled`, `relink-failed`. `unfinished_journals` возвращает журналы в состояниях `start`/`copying`/`verified`/`published`/`backup` и журналы без строки `state` (обрезанная запись); завершённые исходы остаются на диске, но окно о них не предупреждает.
- Порядок и инварианты совпадают с C++: staging → сверка → публикация → резерв → ссылка → сверка → сброс тома → удаление с повторной проверкой. `verify_tree` дополнительно сравнивает набор путей с исходным снимком: пропавший или лишний объект останавливает перенос.
- `verify_source_unchanged` сравнивает размер только у файлов: у каталога `size` — это размер индекса, а не данных (в 2.0.2 сравнение давало ложный отказ на папках с большим числом файлов).
- Отличия Rust-версии: проверка прав на ссылку выполняется пробной ссылкой до создания staging; при неудаче `needs_elevation` выставляется, но автоперезапуск с правами в интерфейсе пока не сделан — пользователь видит текст ошибки.
- Настройки интерфейса: `%LOCALAPPDATA%\Linkerino\settings.txt`, строка `theme=light|dark`; при `--theme` тема берётся из флага и не сохраняется. Папка журналов и настройки не пересекаются: `LINKERINO_JOURNAL_DIR` влияет только на журналы.

### Проверено на Rust

- `cargo test --release -- --test-threads=1`: 18 интеграционных тестов движка и 2 юнит-теста разбора темы, все проходят (NTFS, Windows 10 22H2, права администратора). Без прав на ссылку тесты падают с явным сообщением, а не пропускаются молча; тестовые журналы пишутся во временную папку через `LINKERINO_JOURNAL_DIR` и не попадают в профиль пользователя.
- `basic_move` требует удаления резерва после успеха — это же подтверждает рабочий `flush_volume` на локальном томе.
- `scripts/smoke-rust.ps1`: перенос через `--transfer`, ссылка и данные на месте, окно создаётся и закрывается, три снимка окна (светлая тема, итог, тёмная тема) сохраняются.
- Сборка release: `rust\target\release\Linkerino.exe`, ~3,1 МБ, без импорта `VCRUNTIME140.dll` (статический CRT). Иконка и сведения о версии 2.1.1 встроены в EXE, окно получает ту же иконку.

### Не проверено на Rust

- Приёмники exFAT/FAT32/SMB (в C++ для них есть отдельный скрипт с VHD и SMB-шарой).
- Windows 7/8/8.1 и старые драйверы OpenGL.
- Сбой питания, отключение USB, занятый файл, изменённый источник (сценарии есть только в C++).

## Слои и ответственность (C++)

| Файл | Ответственность |
|---|---|
| `src/win_util.h/.cpp` | RAII `Handle`, пути (канонизация через `GetFinalPathNameByHandleW`, UNC и `\\?\`), сравнение через `CompareStringOrdinal`, проверка тома, определение возможностей ФС (`ProbeFilesystem`), создание ссылок, лог, папка журналов |
| `src/engine.h` | Публичные типы: `Phase`, `Progress`, `ProgressSink`, `Plan`, `Faults`, `Outcome`; функции `BuildPlan`, `Execute`, `FindUnfinishedJournals`, `ReadJournalText`, `PhaseText` |
| `src/engine.cpp` | Снимок дерева, ссылки/junction/жёсткие ссылки, копирование, сверка, публикация, удаление, журнал. Внутренние типы: `Entry`, `EntryStream`, `ReparseInfo`, `FindHandle`, `Sha256`, `ExplicitAcl`, `CopyContext`, `DestinationOptions` |
| `src/main_win32.cpp` | Окно Win32, выбор папок, рабочий поток, прогресс/результат, перезапуск с правами администратора |
| `src/tests/test_main.cpp` | 29 сценариев, 139 проверок; пропуск 77 без прав на ссылку и на сброс тома |
| `scripts/gui-smoke.ps1` | Сквозной оконный сценарий (можно задать свои источник и назначение) |
| `scripts/gui-no-rights.ps1` | Работа без прав администратора: отказ, предложение перезапуска |
| `scripts/test-filesystems.ps1` | VHD с exFAT и FAT32, локальная SMB-шара — реальные прогоны |
| `scripts/capture-ui.ps1` | Снимок окна в `docs/images/linkerino-window.png` |

## Контракты

- `Plan BuildPlan(source_input, dest_parent_input)` — только читает; при ошибке `valid=false` и русский текст в `error`. Источник обязан быть NTFS/ReFS или SMB.
- `Outcome Execute(plan, sink, faults)` — рабочий поток; `leftover` — где остались данные, `notes` — что не перенесено, `needs_elevation` — не хватило прав на ссылку.
- `ProgressSink::OnProgress` вызывается из рабочего потока; `CancelRequested` опрашивается только до фазы `Publish`.
- `ProbeFilesystem(parent)` — локальный NTFS получает всё сразу; ReFS, exFAT/FAT и SMB проверяются пробами: права (установка отдельного ACE и чтение обратно), файловые и каталоговые потоки, жёсткие ссылки, сохранение даты создания, ссылки.
- `Faults` — только для тестов: `copy_failure`, `verify_mismatch`, `link_failure`, `low_space`, `touch_source_after_copy`, `tamper_after_publish`, `break_link_before_delete`, `force_flush_failure`, `break_link_after_files`.
- Журнал: `%LOCALAPPDATA%\Linkerino\journal-<guid>.txt`; состояния `start`, `copying`, `verified`, `published`, `backup`, `linked`, `cleanup-partial`, `cleanup-skipped`, `cleanup-skipped-durability`, `link-lost`, `failed`, `cancelled`, `relink-failed`.

## Поток выполнения

`BuildPlan` → `Execute`:

1. Preflight: `ProbeSymlink` рядом с исходной папкой, проверка служебных имён, создание staging.
2. `ScanDir` → `std::vector<Entry>`: идентификатор, размер, даты, атрибуты, DACL, потоки через `FileStreamInfo`, reparse-данные (цель, тег, относительность), группы жёстких ссылок. Отказ только на EFS, offline и облачных заглушках.
3. `ProbeFilesystem(dest)` и `DestinationOptions`: что копировать и с какой точностью проверять.
4. `CopyTree` → staging: каталоги (DACL/потоки), ссылки и junction (с прежними целями), файлы (данные, потоки, DACL, даты, атрибуты), жёсткие ссылки — `CreateHardLinkW`.
5. `VerifyTree` — набор путей (сортировка), типы, размеры, даты с допуском ФС, DACL (если поддерживается), хэши, цели ссылок, число жёстких ссылок; `VerifySourceUnchanged` — идентификаторы, ссылки, хэши.
6. `RenameWithRetry(staging → dest_final)`, фиксация тома/индекса, `FlushVolume`.
7. `MoveFileEx(source → backup)` → ссылка → `VerifySymlink` (тег, цель, идентификатор каталога).
8. Перед удалением: повторная проверка ссылки и полная сверка копии (без опроса отмены); на локальном томе — `FlushVolume`, иначе резерв сохраняется. На сетевом томе подтверждением считается сброс каждого файла.
9. `DeleteBackupTree` — обратный обход: проверка идентификатора, размера, даты, хэшей, reparse-цели; ссылка проверяется каждые 32 элемента; при сбое остаток сохраняется.

## Инварианты

- До публикации исходная папка не изменяется.
- Любое удаление предваряется повторной проверкой; при расхождении удаление прекращается.
- Ссылки внутри папки пересоздаются с исходной целью; жёсткие ссылки — с тем же набором имён.
- DACL копируется явным (protected) ACL; сравнение не зависит от флага наследования ACE.
- Дескрипторы перечисления закрываются только `FindClose` (`FindHandle`).
- Отмена не прерывает переключение: кнопка гаснет на фазах `Publish`, `Link`, `Cleanup`.

## Ограничения, заложенные в код

- Источник — NTFS/ReFS или SMB (иначе ссылку не создать), назначение — NTFS/ReFS/exFAT/FAT32/SMB.
- На FAT/exFAT и части SMB-шар не переносятся ACL, потоки и вложенные ссылки; жёсткие ссылки там копируются как отдельные файлы; всё это видно в `Outcome.notes`.
- Группировка жёстких ссылок доверяет паре «том+индекс» и совпадению хэша: на источнике с неуникальными индексами (некоторые SMB/NAS) независимые файлы с одинаковым содержимым могут стать одной жёсткой ссылкой. Данные не теряются, но связь файлов может отличаться от исходной.
- Подтверждение записи тома требует прав администратора; на сетевом томе не проверяется.
- Копия сверяется один раз перед удалением; во время удаления проверяется доступность ссылки каждые 32 элемента.
