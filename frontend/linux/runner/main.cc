// Thin entry point for `flutter run` compatibility.
//
// The DEPLOYED entry point is the Rust binary (meshinfinity), which loads
// libflutter_ui.so at runtime.  This executable exists solely so that
// `flutter run -d linux` works during development.

#include "my_application.h"

int main(int argc, char** argv) {
  g_autoptr(MyApplication) app = my_application_new();
  return g_application_run(G_APPLICATION(app), argc, argv);
}
