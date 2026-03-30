cmake_minimum_required(VERSION 3.13)
project(runner LANGUAGES CXX)

# GTK is required for the Flutter Linux embedding.
find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK REQUIRED IMPORTED_TARGET gtk+-3.0)

# ── Flutter UI shared library ─────────────────────────────────────────────────
#
# The Flutter GTK runner is compiled as a shared library (libflutter_ui.so)
# that exports flutter_start().  The actual deployed entry point is the Rust
# binary (meshinfinity) which links this library — Flutter is not authoritative.

add_library(flutter_ui SHARED
  "app_entry.cc"
  "my_application.cc"
  "${FLUTTER_MANAGED_DIR}/generated_plugin_registrant.cc"
)

# Inlined from apply_standard_settings (removed in Flutter 3.41+):
set_target_properties(flutter_ui PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)
target_compile_options(flutter_ui PRIVATE -Wall -Werror)
target_compile_options(flutter_ui PRIVATE "$<$<NOT:$<CONFIG:Debug>>:-O3>")
target_compile_definitions(flutter_ui PRIVATE "$<$<NOT:$<CONFIG:Debug>>:NDEBUG>")
target_compile_definitions(flutter_ui PRIVATE APPLICATION_ID="${APPLICATION_ID}")
target_link_libraries(flutter_ui PUBLIC flutter)
target_link_libraries(flutter_ui PRIVATE PkgConfig::GTK)
target_include_directories(flutter_ui PRIVATE "${CMAKE_SOURCE_DIR}")

set_target_properties(flutter_ui PROPERTIES
  VERSION   1.0.0
  SOVERSION 1
  OUTPUT_NAME "flutter_ui"
)

# ── Compatibility executable ──────────────────────────────────────────────────
#
# A thin wrapper that just calls flutter_start().  Exists only so that
# `flutter run` (which execs this binary) continues to work during development.
# It is NOT the deployed entry point and is excluded from release packaging.

add_executable(${BINARY_NAME} "main.cc")
# Inlined from apply_standard_settings (removed in Flutter 3.41+):
set_target_properties(${BINARY_NAME} PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)
target_compile_options(${BINARY_NAME} PRIVATE -Wall -Werror)
target_compile_options(${BINARY_NAME} PRIVATE "$<$<NOT:$<CONFIG:Debug>>:-O3>")
target_compile_definitions(${BINARY_NAME} PRIVATE "$<$<NOT:$<CONFIG:Debug>>:NDEBUG>")
target_link_libraries(${BINARY_NAME} PRIVATE flutter_ui)
target_include_directories(${BINARY_NAME} PRIVATE "${CMAKE_SOURCE_DIR}")
