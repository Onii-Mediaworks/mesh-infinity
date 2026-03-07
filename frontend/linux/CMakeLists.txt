cmake_minimum_required(VERSION 3.13)
project(runner LANGUAGES CXX)

# Flutter names the runner binary after the pubspec name field.
# This is an internal implementation detail — the deployed entry point is
# the Rust binary (meshinfinity) which links libflutter_ui.so.
set(BINARY_NAME "mesh_infinity_frontend")
set(APPLICATION_ID "dev.meshinfinity.app")

cmake_policy(SET CMP0063 NEW)

set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/bundle"
    CACHE PATH "Installation prefix for build artifacts" FORCE)

if(FLUTTER_TARGET_PLATFORM_OVERRIDE)
  set(FLUTTER_TARGET_PLATFORM "${FLUTTER_TARGET_PLATFORM_OVERRIDE}")
endif()

# Flutter-managed generated files live here.
set(FLUTTER_MANAGED_DIR "${CMAKE_CURRENT_SOURCE_DIR}/flutter")

add_subdirectory("runner")

# Generated plugin build rules (produced by `flutter pub get`).
include(flutter/generated_plugins.cmake)

# ── Installation ──────────────────────────────────────────────────────────────

# Thin executable (for `flutter run` compatibility).
install(TARGETS ${BINARY_NAME} RUNTIME DESTINATION "${CMAKE_INSTALL_PREFIX}"
        COMPONENT Runtime)

# The Flutter UI shared library — linked by the Rust binary at runtime.
install(TARGETS flutter_ui LIBRARY DESTINATION "${CMAKE_INSTALL_PREFIX}/lib"
        COMPONENT Runtime)

install(FILES "${FLUTTER_ICU_DATA_FILE}"
        DESTINATION "${CMAKE_INSTALL_PREFIX}/data" COMPONENT Runtime)

install(FILES "${FLUTTER_LIBRARY}"
        DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" COMPONENT Runtime)

foreach(bundled_library ${PLUGIN_BUNDLED_LIBRARIES})
  install(FILES "${bundled_library}"
          DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" COMPONENT Runtime)
endforeach(bundled_library)

# Wipe and re-copy Flutter assets on every build to avoid stale files.
set(FLUTTER_ASSET_DIR_NAME "flutter_assets")
install(CODE "
  file(REMOVE_RECURSE \"${CMAKE_INSTALL_PREFIX}/data/${FLUTTER_ASSET_DIR_NAME}\")
  " COMPONENT Runtime)
install(DIRECTORY "${PROJECT_BUILD_DIR}/${FLUTTER_ASSET_DIR_NAME}"
        DESTINATION "${CMAKE_INSTALL_PREFIX}/data" COMPONENT Runtime)

# AOT snapshot only present in non-Debug configurations.
install(FILES "${AOT_LIBRARY}"
        DESTINATION "${CMAKE_INSTALL_PREFIX}/lib"
        CONFIGURATIONS Release COMPONENT Runtime)
