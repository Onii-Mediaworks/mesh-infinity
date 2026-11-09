package com.oniimediaworks.meshinfinity.uispike

import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.util.concurrent.LinkedBlockingQueue

/**
 * The stand-in core's end of the protocol socket, in the main process.
 * The real protocol (typed Protocol Buffers frames) is spike S5; here each
 * SOCK_SEQPACKET packet is one UTF-8 text message, enough to show that a
 * confined UI can still talk to its core:
 * - `ping` -> `pong`
 * - `echo <text>` -> `echo: <text>` (the UI shows the reply)
 * - `report <json>` -> stored in [reports] for the instrumented test, and logged.
 */
object CoreStub {
    private const val TAG = "MeshUiSpike"

    /** The reports UI processes sent, oldest first. The test, in this process, takes them. */
    val reports = LinkedBlockingQueue<String>()

    /** Serves [socket] on a thread of its own until the UI process closes it or dies. */
    fun serve(socket: ParcelFileDescriptor) {
        Thread({ run(socket) }, "core-stub").apply { isDaemon = true }.start()
    }

    private fun run(socket: ParcelFileDescriptor) {
        val input = FileInputStream(socket.fileDescriptor)
        val output = FileOutputStream(socket.fileDescriptor)
        // One packet per read; 64 KiB is far above any message here.
        val buffer = ByteArray(64 * 1024)
        try {
            while (true) {
                val length = input.read(buffer)
                // End of stream: the UI process closed the socket or died.
                if (length <= 0) break
                val message = String(buffer, 0, length, Charsets.UTF_8)
                val reply = answer(message) ?: continue
                output.write(reply.toByteArray(Charsets.UTF_8))
            }
        } catch (error: IOException) {
            Log.i(TAG, "UI session ended: ${error.message}")
        } finally {
            socket.close()
        }
        Log.i(TAG, "UI session closed")
    }

    /** The reply to one message, or null when it needs none. */
    private fun answer(message: String): String? = when {
        message == "ping" -> "pong"
        message.startsWith("echo ") -> "echo: " + message.removePrefix("echo ")
        message.startsWith("report ") -> {
            val report = message.removePrefix("report ")
            Log.i(TAG, "REPORT $report")
            reports.put(report)
            null
        }
        else -> "error: unknown message"
    }
}
