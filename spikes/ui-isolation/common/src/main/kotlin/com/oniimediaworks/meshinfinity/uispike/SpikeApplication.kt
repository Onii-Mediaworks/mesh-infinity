package com.oniimediaworks.meshinfinity.uispike

import android.app.Application
import android.os.Build
import java.io.File

/**
 * Runs in both processes. In the `:ui` process it attaches to the core and
 * locks the process down before any Activity exists, so no UI code runs
 * unconfined. The main process does nothing here; the provider starts the
 * core stand-in when it is first called.
 */
class SpikeApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        // Only the UI process confines itself.
        if (process_name().endsWith(":ui")) UiSession.start(this)
    }

    /** This process's name; API 28 has a call for it, older versions read /proc. */
    private fun process_name(): String =
        if (Build.VERSION.SDK_INT >= 28) Application.getProcessName()
        else File("/proc/self/cmdline").readText().trimEnd('\u0000')
}
