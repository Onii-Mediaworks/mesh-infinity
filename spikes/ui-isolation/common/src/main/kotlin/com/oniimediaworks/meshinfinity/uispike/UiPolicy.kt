package com.oniimediaworks.meshinfinity.uispike

import android.content.Context
import com.oniimediaworks.meshinfinity.uispike.NativeSandbox.SBX_READ
import com.oniimediaworks.meshinfinity.uispike.NativeSandbox.SBX_WRITE
import java.io.File

/**
 * The broker's rules for the UI process (the `MESH_UI` policy, first draft).
 * Starts from Enginehost's rules for a GPU-using ART process, minus
 * everything that holds app data: the UI gets the system's code and data,
 * its own APK and native libraries, the devices graphics and ART need, and
 * its code cache. It gets nothing under filesDir, where the core keeps the
 * vault. A learning run reports what else a real UI asks for.
 */
object UiPolicy {
    /** The devices the UI process opens itself before the lockdown. */
    val OWN_OPENS = arrayOf("/dev/hwbinder", "/dev/kgsl-3d0", "/dev/mali0", "/dev/dri/renderD128")

    fun rules(context: Context): Map<String, Int> {
        val rules = LinkedHashMap<String, Int>()

        // The system's code and data. /proc is limited by the broker to the
        // caller's own entries; other processes' entries are never served.
        listOf(
            "/system", "/system_ext", "/product", "/vendor", "/odm", "/apex", "/linkerconfig",
            "/data/dalvik-cache", "/data/fonts", "/data/resource-cache", "/data/misc/zoneinfo",
            "/proc", "/sys", "/dev/__properties__",
            // The app's own code.
            File(context.applicationInfo.sourceDir).parent ?: context.applicationInfo.sourceDir,
            context.applicationInfo.nativeLibraryDir,
        ).forEach { rules[it] = SBX_READ }

        // Devices graphics, ART and binder open after the lockdown.
        val ashmem = runCatching {
            "/dev/ashmem" + File("/proc/sys/kernel/random/boot_id").readText().trim()
        }.getOrNull()
        listOfNotNull(
            "/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/ashmem", ashmem,
            "/dev/binder", "/dev/hwbinder", "/dev/vndbinder", "/dev/kgsl-3d0", "/dev/ion", "/dev/dma_heap",
            "/dev/dri", "/dev/mali0",
            // The emulator's graphics pipes.
            "/dev/goldfish_pipe", "/dev/goldfish_pipe_dprctd", "/dev/goldfish_sync",
            "/dev/goldfish_address_space", "/dev/qemu_pipe",
        ).forEach { rules[it] = SBX_READ or SBX_WRITE }

        // The code cache: ART and the renderer's shader cache. Holds no core data.
        rules[context.codeCacheDir.absolutePath] = SBX_READ or SBX_WRITE
        // ART's profile of this app's hot code, which profile-guided compilation
        // uses to make later starts faster (S1 learning run, API 34). It is
        // the system's file about this app and holds no app data.
        rules["/data/misc/profiles/cur/0/${context.packageName}"] = SBX_READ or SBX_WRITE
        return rules
    }
}
