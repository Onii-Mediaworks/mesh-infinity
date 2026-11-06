package com.oniimediaworks.meshinfinity.uispike

/**
 * The JNI surface of `ui_sandbox.c`: the Fibrewall broker (main process),
 * the lockdown (`:ui` process) and the escape probes.
 *
 * Every probe returns 0 when the system call succeeded, which for a
 * confined UI is an escape, or a negative errno when it was refused.
 */
object NativeSandbox {
    init {
        // One library for both processes.
        System.loadLibrary("mesh_ui_sandbox")
    }

    /** Fibrewall rule modes, as in `sbx.h`. */
    const val SBX_READ = 1
    const val SBX_WRITE = 2

    /** Main process: serve [fd] under [paths]/[modes]; takes ownership of [fd]. */
    @JvmStatic external fun serve0(fd: Int, paths: Array<String>, modes: IntArray, learn: Boolean): Int

    /** `:ui` process: lock this process down on [fd]; takes ownership of [fd]. */
    @JvmStatic external fun lockdown0(fd: Int, own_opens: Array<String>, learn: Boolean): Int

    /** Open [path] read-only. */
    @JvmStatic external fun probeOpen(path: String): Int

    /** Create an AF_INET stream socket. */
    @JvmStatic external fun probeInetSocket(): Int

    /** PTRACE_ATTACH to [pid]. */
    @JvmStatic external fun probePtrace(pid: Int): Int

    /** Send signal 0 to [pid]. */
    @JvmStatic external fun probeSignal(pid: Int): Int

    /** Fork and execve `/system/bin/true`. */
    @JvmStatic external fun probeExec(): Int
}
