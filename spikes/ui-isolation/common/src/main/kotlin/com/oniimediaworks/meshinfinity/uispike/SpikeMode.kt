package com.oniimediaworks.meshinfinity.uispike

import android.content.Context
import java.io.File

/**
 * How the next UI process runs, chosen by the main process (the test
 * writes it before launching the UI):
 * - [OFF]: no lockdown, the unconfined baseline;
 * - [LEARN]: locked down, nothing refused, every would-be refusal logged;
 * - [ENFORCE]: locked down under the UI policy.
 */
object SpikeMode {
    const val OFF = "off"
    const val LEARN = "learn"
    const val ENFORCE = "enforce"
    private const val FILE = "spike_mode"

    /** The mode for the next attach; enforcing unless set. */
    fun read(context: Context): String =
        runCatching { File(context.filesDir, FILE).readText().trim() }.getOrNull()
            ?.takeIf { it == OFF || it == LEARN || it == ENFORCE } ?: ENFORCE

    /** Sets the mode for the next attach. */
    fun write(context: Context, mode: String) = File(context.filesDir, FILE).writeText(mode)
}
