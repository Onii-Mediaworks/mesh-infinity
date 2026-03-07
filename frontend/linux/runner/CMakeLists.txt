cmake_minimum_required(VERSION 3.13)
project(runner LANGUAGES CXX)

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

apply_standard_settings(flutter_ui)
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
apply_standard_settings(${BINARY_NAME})
target_link_libraries(${BINARY_NAME} PRIVATE flutter_ui)
target_include_directories(${BINARY_NAME} PRIVATE "${CMAKE_SOURCE_DIR}")
