cmake_minimum_required(VERSION 3.16)
project(Linkerino LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if (NOT MSVC)
  message(FATAL_ERROR "Linkerino targets MSVC (Visual Studio 2019+).")
endif()

if (NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(FATAL_ERROR "Linkerino must be configured for Win32 (32-bit). Use -A Win32.")
endif()

add_compile_definitions(UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0601 WINVER=0x0601)
add_compile_options(/W4 /permissive- /utf-8 /EHsc)

add_library(linkerino_core STATIC
  src/win_util.cpp
  src/engine.cpp
)
target_include_directories(linkerino_core PUBLIC src)
target_link_libraries(linkerino_core PUBLIC
  bcrypt advapi32 user32 shell32 ole32 oleaut32 shlwapi
)

add_executable(Linkerino WIN32 src/main_win32.cpp)
target_link_libraries(Linkerino PRIVATE linkerino_core comctl32)
target_link_options(Linkerino PRIVATE "/SUBSYSTEM:WINDOWS,6.01")

add_executable(linkerino_tests src/tests/test_main.cpp)
target_link_libraries(linkerino_tests PRIVATE linkerino_core)
target_link_options(linkerino_tests PRIVATE "/SUBSYSTEM:CONSOLE,6.01")

enable_testing()
add_test(NAME linkerino_tests COMMAND linkerino_tests)
set_tests_properties(linkerino_tests PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 300)
