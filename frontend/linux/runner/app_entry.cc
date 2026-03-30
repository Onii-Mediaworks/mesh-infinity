// Shared library entry point for the Flutter UI.
//
// When built as a shared library (libflutter_ui.so), the Rust binary calls
// flutter_start() to initialise GTK + Flutter.  This decouples the Flutter
// lifecycle from the Rust lifecycle: the Rust side owns the process and
// decides when to start the UI.

#include "my_application.h"

// Exported symbol that the Rust binary calls via dlopen/dlsym.
extern "C" __attribute__((visibility("default")))
int flutter_start(int argc, char** argv) {
  g_autoptr(MyApplication) app = my_application_new();
  return g_application_run(G_APPLICATION(app), argc, argv);
}
