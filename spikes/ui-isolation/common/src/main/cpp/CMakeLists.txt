cmake_minimum_required(VERSION 3.22.1)
project(mesh_ui_spike C)

# The spike's JNI library: the broker side (main process), the confined
# side (`:ui` process) and the escape probes, over Fibrewall.
add_library(mesh_ui_sandbox SHARED ui_sandbox.c)

# Fibrewall, pinned as the repository's vendor/fibrewall submodule (v0.6.1).
# Only its static library is built; its own tests are off.
set(SBX_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../vendor/fibrewall
                 ${CMAKE_CURRENT_BINARY_DIR}/fibrewall)

target_link_libraries(mesh_ui_sandbox PRIVATE sbx log)
