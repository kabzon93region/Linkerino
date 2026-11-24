# Linkerino — правила проекта

- Назначение: переносимая программа Windows для переноса папки и замены её символьной ссылкой каталога.
- Стек: C++17, Win32 API, CMake, MSVC (VS2019 Build Tools), x86, статический CRT, `_WIN32_WINNT=0x0601`.
- Точка входа: `src/main_win32.cpp`. Уровень документации: STANDARD.
- Правила: `docs/superpowers/specs/2026-11-24-linkerino-design.md`, план — `docs/superpowers/plans/2026-11-24-linkerino.md`.

## Команды (проверены при сборке)

| Действие | Команда |
|---|---|
| Конфигурация | `cmake -S . -B build/win32 -G "Visual Studio 16 2019" -A Win32` |
| Сборка | `cmake --build build/win32 --config Release` |
| Тесты | `ctest --test-dir build/win32 -C Release --output-on-failure` |
| Запуск | `build\win32\Release\Linkerino.exe` |

## Структура

```
src/          интерфейс, движок, утилиты
src/tests/    нативные интеграционные тесты
docs/         спецификация, план, карта кода
build/        артефакты CMake (не читать, не коммитить)
```

- Не трогать реальные папки пользователя (`C:\atiflash`, `B:\BKP`) — все проверки только на временных каталогах.
- Не использовать .NET, WSL, Docker, сторонние библиотеки.

## Соглашения

- Код и логи — английский, тексты интерфейса — русский. Скрипты `.cmd`/`.ps1` — только ASCII.
- Любая операция удаления обязана иметь повторную проверку идентичности и содержимого.
- Карта кода: `docs/architecture/CODE_MAP.md`.
