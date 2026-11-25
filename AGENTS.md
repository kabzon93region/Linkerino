# Linkerino — правила проекта

- Назначение: переносимая программа Windows для переноса папки и замены её символьной ссылкой каталога.
- Стек 1.1: C++17, Win32 API, CMake, MSVC (VS2019 Build Tools), x86, статический CRT, `_WIN32_WINNT=0x0601`.
- Стек 2.0: Rust (edition 2021), `windows-sys`, `eframe`/`egui`, x86_64; интерфейс — `rust/src/main.rs`.
- Точка входа: `src/main_win32.cpp` (C++), `rust/src/main.rs` (Rust). Уровень документации: STANDARD.
- Правила: `docs/superpowers/specs/2026-11-24-linkerino-design.md`, план — `docs/superpowers/plans/2026-11-24-linkerino.md`.

## Команды (проверены при сборке)

| Действие | Команда |
|---|---|
| Конфигурация | `cmake -S . -B build/win32 -G "Visual Studio 16 2019" -A Win32` |
| Сборка | `cmake --build build/win32 --config Release` |
| Тесты | `ctest --test-dir build/win32 -C Release --output-on-failure` |
| Запуск | `build\win32\Release\Linkerino.exe` |
| Сборка Rust | `cargo build --release --manifest-path rust\Cargo.toml` |
| Тесты Rust | `cargo test --release --manifest-path rust\Cargo.toml -- --test-threads=1` |
| Запуск Rust | `rust\target\release\Linkerino.exe` |
| Дымовой тест Rust | `powershell -ExecutionPolicy Bypass -File scripts\smoke-rust.ps1` |

## Структура

```
src/          интерфейс, движок, утилиты (C++)
src/tests/    нативные интеграционные тесты (C++)
rust/src/     движок и интерфейс на Rust
rust/tests/   интеграционные тесты движка Rust
rust/assets/  иконка: linkerino.ico и PNG-варианты
rust/build.rs ресурсы Windows: иконка и сведения о версии
.cargo/       config.toml: статический CRT для Rust (+crt-static)
docs/         спецификация, план, карта кода
build/        артефакты CMake (не читать, не коммитить)
rust/target/  артефакты cargo (не читать, не коммитить)
```

- Не трогать реальные папки пользователя (`C:\atiflash`, `B:\BKP`) — все проверки только на временных каталогах.
- Не использовать .NET, WSL, Docker, сторонние библиотеки. Исключение — Rust-сборка: только crates из `rust/Cargo.toml` (`eframe`/`egui`, `sha2`, `rfd`, `windows-sys`, `image`; сборочная зависимость `winres` для иконки и версии). `Pillow` в `scripts/make-icon.py` — только dev-инструмент, в поставку не входит.

## Соглашения

- Код и логи — английский, тексты интерфейса — русский. Скрипты `.cmd`/`.ps1` — только ASCII.
- Любая операция удаления обязана иметь повторную проверку идентичности и содержимого.
- Карта кода: `docs/architecture/CODE_MAP.md`.
