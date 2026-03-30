// GTK application implementation for the Flutter Linux runner.
//
// Sets up a GTK window, embeds a FlView (the Flutter rendering surface),
// and connects keyboard/mouse events to the Flutter engine.

#include "my_application.h"

#include <flutter_linux/flutter_linux.h>
#ifdef GDK_WINDOWING_X11
#include <gdk/gdkx.h>
#endif

#include "flutter/generated_plugin_registrant.h"

struct _MyApplication {
  GtkApplication parent_instance;
  char** dart_entrypoint_arguments;
};

G_DEFINE_TYPE(MyApplication, my_application, GTK_TYPE_APPLICATION)

// Called when the application is activated (window creation).
static void my_application_activate(GApplication* application) {
  MyApplication* self = MY_APPLICATION(application);

  // Create the main window with a reasonable default size.
  GtkWindow* window =
      GTK_WINDOW(gtk_application_window_new(GTK_APPLICATION(application)));

  // Use the GTK header bar for the title bar on supported platforms.
  GtkHeaderBar* header_bar = GTK_HEADER_BAR(gtk_header_bar_new());
  gtk_widget_show(GTK_WIDGET(header_bar));
  gtk_header_bar_set_title(header_bar, "Mesh Infinity");
  gtk_header_bar_set_show_close_button(header_bar, TRUE);
  gtk_window_set_titlebar(window, GTK_WIDGET(header_bar));

  gtk_window_set_default_size(window, 1280, 720);
  gtk_widget_show(GTK_WIDGET(window));

  // Create the Flutter project (locates assets and AOT snapshot).
  g_autoptr(FlDartProject) project = fl_dart_project_new();
  fl_dart_project_set_dart_entrypoint_arguments(
      project, self->dart_entrypoint_arguments);

  // Create the Flutter view and embed it in the window.
  FlView* view = fl_view_new(project);
  gtk_widget_show(GTK_WIDGET(view));
  gtk_container_add(GTK_CONTAINER(window), GTK_WIDGET(view));

  // Register plugins after the view is created.
  fl_register_plugins(FL_PLUGIN_REGISTRY(view));

  // Grab keyboard focus so the Flutter engine receives key events.
  gtk_widget_grab_focus(GTK_WIDGET(view));
}

// GObject lifecycle: handle command-line arguments.
static gint my_application_local_command_line(GApplication* application,
                                              gchar*** arguments,
                                              int* exit_status) {
  MyApplication* self = MY_APPLICATION(application);

  // Strip the program name (argv[0]) and store the rest for Dart.
  self->dart_entrypoint_arguments = g_strdupv(*arguments + 1);

  g_autoptr(GError) error = nullptr;
  if (!g_application_register(application, nullptr, &error)) {
    g_warning("Failed to register: %s", error->message);
    *exit_status = 1;
    return TRUE;
  }

  g_application_activate(application);
  *exit_status = 0;

  return TRUE;
}

// GObject lifecycle: clean up Dart arguments.
static void my_application_dispose(GObject* object) {
  MyApplication* self = MY_APPLICATION(object);
  g_strfreev(self->dart_entrypoint_arguments);
  G_OBJECT_CLASS(my_application_parent_class)->dispose(object);
}

// GObject class initialisation.
static void my_application_class_init(MyApplicationClass* klass) {
  G_APPLICATION_CLASS(klass)->activate = my_application_activate;
  G_APPLICATION_CLASS(klass)->local_command_line =
      my_application_local_command_line;
  G_OBJECT_CLASS(klass)->dispose = my_application_dispose;
}

// GObject instance initialisation (no-op).
static void my_application_init(MyApplication* self) {}

// Public constructor.
MyApplication* my_application_new() {
  return MY_APPLICATION(g_object_new(
      my_application_get_type(), "application-id", APPLICATION_ID, "flags",
      G_APPLICATION_NON_UNIQUE, nullptr));
}
