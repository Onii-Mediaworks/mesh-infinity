cmake_minimum_required(VERSION 3.13)
project(runner LANGUAGES CXX)

# Define the application target. To change its name, change BINARY_NAME in the
# top-level CMakeLists.txt, not the value here, or `flutter run` will no longer
# work.
#
# Any new source files that you add to the application should be added here.
add_executable(${BINARY_NAME}
  "main.cc"
  "my_application.cc"
  "${FLUTTER_MANAGED_DIR}/generated_plugin_registrant.cc"
)

# Apply the standard set of build settings.
# Inlined here for compatibility across Flutter versions (apply_standard_settings
# may or may not be defined in the parent scope depending on Flutter version).
if(COMMAND apply_standard_settings)
  apply_standard_settings(${BINARY_NAME})
else()
  target_compile_features(${BINARY_NAME} PUBLIC cxx_std_14)
  target_compile_options(${BINARY_NAME} PRIVATE -Wall -Werror)
  target_compile_options(${BINARY_NAME} PRIVATE "$<$<NOT:$<CONFIG:Debug>>:-O3>")
  target_compile_definitions(${BINARY_NAME} PRIVATE "$<$<NOT:$<CONFIG:Debug>>:NDEBUG>")
endif()

# Add preprocessor definitions for the application ID.
add_definitions(-DAPPLICATION_ID="${APPLICATION_ID}")

# Add dependency libraries. Add any application-specific dependencies here.
target_link_libraries(${BINARY_NAME} PRIVATE flutter)
target_link_libraries(${BINARY_NAME} PRIVATE PkgConfig::GTK)

target_include_directories(${BINARY_NAME} PRIVATE "${CMAKE_SOURCE_DIR}")
