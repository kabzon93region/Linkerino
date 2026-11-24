# Карта кода: Linkerino

Обновлено: 2026-11-25 (версия 1.1). Источник истины — код; карта помогает навигации.

## Слои и ответственность

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
