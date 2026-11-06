package com.oniimediaworks.meshinfinity.uispike

import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.os.Process
import android.util.Log
import org.json.JSONObject
import java.io.FileInputStream
import java.io.FileOutputStream

/**
 * The UI process's side of the split, started from Application.onCreate in
 * `:ui` before any Activity exists:
 * 1. create the broker and protocol socket pairs;
 * 2. hand the protocol end to the core ([UiHostProvider]) and the broker end
 *    to the warden ([WardenProvider]), which serves it under the policy the
 *    core grants;
 * 3. lock the process down on the broker socket (unless the run is the baseline);
 * 4. run the escape probes and report them to the core.
 */
object UiSession {
    private const val TAG = "MeshUiSpike"

    /** This run's mode, as the core chose it. */
    var mode: String = "none"
        private set

    /** The lockdown's result: 0 confined, a negative errno, or null when not attempted. */
    var confined: Int? = null
        private set

    /** Each probe's result: 0 = the call succeeded, negative = refused (errno). */
    var probes: Map<String, Int> = emptyMap()
        private set

    /** The warden's pid, for the probes against it. */
    private var warden_pid = 0

    private var input: FileInputStream? = null
    private var output: FileOutputStream? = null

    fun start(context: Context) {
        // Both pairs are SOCK_SEQPACKET, which Fibrewall's broker requires.
        val broker = ParcelFileDescriptor.createReliableSocketPair()
        val protocol = ParcelFileDescriptor.createReliableSocketPair()

        // 1. The app channel to the core, which answers the run's mode.
        val reply = try {
            context.contentResolver.call(
                Uri.parse("content://" + UiHostProvider.authority(context)), UiHostProvider.METHOD_ATTACH, null,
                Bundle().apply { putParcelable(UiHostProvider.KEY_PROTOCOL, protocol[0]) },
            )
        } finally {
            protocol[0].close()
        }
        // 2. The broker channel to the warden, which gets this worker's policy from the core.
        val warden = try {
            if (reply == null) null else context.contentResolver.call(
                Uri.parse("content://" + WardenProvider.authority(context)), WardenProvider.METHOD_BROKER, null,
                Bundle().apply { putParcelable(WardenProvider.KEY_BROKER, broker[0]) },
            )
        } finally {
            broker[0].close()
        }
        if (reply == null || warden == null) {
            // No core or no warden: the UI must not run unconfined by accident.
            Log.e(TAG, "attach refused (core ${reply != null}, warden ${warden != null}); stopping the UI process")
            Process.killProcess(Process.myPid())
            return
        }
        mode = warden.getString(UiHostProvider.KEY_MODE) ?: SpikeMode.ENFORCE
        warden_pid = warden.getInt(WardenProvider.KEY_WARDEN_PID)

        // 3. Lock down before anything else runs in this process.
        if (mode == SpikeMode.OFF) {
            broker[1].close()
        } else {
            confined = NativeSandbox.lockdown0(broker[1].detachFd(), UiPolicy.OWN_OPENS, mode == SpikeMode.LEARN)
            if (confined != 0 && mode == SpikeMode.ENFORCE) {
                Log.e(TAG, "lockdown failed ($confined); stopping the UI process")
                Process.killProcess(Process.myPid())
                return
            }
        }
        input = FileInputStream(protocol[1].fileDescriptor)
        output = FileOutputStream(protocol[1].fileDescriptor)

        // What a compromised UI would try: the core's files, network, the core's memory.
        val core_pid = reply.getInt(UiHostProvider.KEY_CORE_PID)
        val secret = reply.getString(UiHostProvider.KEY_SECRET) ?: ""
        probes = linkedMapOf(
            "open_core_secret" to NativeSandbox.probeOpen(secret),
            "open_core_proc_mem" to NativeSandbox.probeOpen("/proc/$core_pid/mem"),
            "open_core_proc_maps" to NativeSandbox.probeOpen("/proc/$core_pid/maps"),
            "open_app_data_dir" to NativeSandbox.probeOpen(context.applicationInfo.dataDir),
            "inet_socket" to NativeSandbox.probeInetSocket(),
            "ptrace_core" to NativeSandbox.probePtrace(core_pid),
            "open_warden_proc_mem" to NativeSandbox.probeOpen("/proc/$warden_pid/mem"),
            "ptrace_warden" to NativeSandbox.probePtrace(warden_pid),
            "signal_core" to NativeSandbox.probeSignal(core_pid),
            "exec" to NativeSandbox.probeExec(),
            "ping_core" to if (request("ping") == "pong") 0 else -1,
        )
        send("report " + report(core_pid))
    }

    /** One request and its reply over the protocol socket. */
    @Synchronized
    fun request(message: String): String? {
        send(message)
        val buffer = ByteArray(64 * 1024)
        val length = input?.read(buffer) ?: return null
        return if (length > 0) String(buffer, 0, length, Charsets.UTF_8) else null
    }

    private fun send(message: String) {
        output?.write(message.toByteArray(Charsets.UTF_8))
    }

    private fun report(core_pid: Int): String = JSONObject().apply {
        put("mode", mode)
        put("confined", confined ?: JSONObject.NULL)
        put("sdk", Build.VERSION.SDK_INT)
        put("ui_pid", Process.myPid())
        put("core_pid", core_pid)
        put("warden_pid", warden_pid)
        put("probes", JSONObject(probes as Map<*, *>))
    }.toString()
}
