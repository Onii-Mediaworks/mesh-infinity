package com.oniimediaworks.meshinfinity.uispike

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.os.Process
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.Direction
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.TimeUnit

/**
 * Spike S1's measurements and gates, shared by the Compose and the Flutter
 * host. Runs in the app's main process (the stand-in core), launches the
 * confined UI three times — baseline, learning,
 * enforcing — and drives it the way a person would.
 *
 * Every run logs one `MeshUiSpike RESULT <json>` line; the CI job collects
 * those with the broker's `MeshUiBroker` records. The gates (assertions)
 * are only what the spike must prove: under enforcement the probes are
 * refused and the UI still works as well as the baseline.
 */
@RunWith(AndroidJUnit4::class)
class UiIsolationSpikeTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context: Context = instrumentation.targetContext
    private val device = UiDevice.getInstance(instrumentation)
    private val pkg = context.packageName

    @Test
    fun confined_ui_matches_baseline() {
        val baseline = run_ui(SpikeMode.OFF)
        val learning = run_ui(SpikeMode.LEARN)
        val enforcing = run_ui(SpikeMode.ENFORCE)

        // The lockdown itself.
        assertEquals("learning lockdown", 0, learning.getInt("confined"))
        assertEquals("enforcing lockdown", 0, enforcing.getInt("confined"))

        // Under enforcement every escape probe is refused, and the core is still reachable.
        val probes = enforcing.getJSONObject("probes")
        for (name in probes.keys()) {
            val result = probes.getInt(name)
            if (name == "ping_core") assertEquals("ping_core", 0, result)
            else assertTrue("$name must be refused, got $result", result < 0)
        }

        // The UI works as well confined as unconfined.
        for (check in listOf("echo_round_trip", "typed_text", "survived_rotation", "ime_shown")) {
            assertEquals(check, baseline.getBoolean(check), enforcing.getBoolean(check))
        }
        assertTrue("echo round trip", enforcing.getBoolean("echo_round_trip"))
    }

    /** Launches the UI under [mode], drives it, and returns its result. */
    private fun run_ui(mode: String): JSONObject {
        kill_ui()
        CoreStub.reports.clear()
        SpikeMode.write(context, mode)
        // The host app's own UI (Compose or Flutter), through its launcher intent.
        val launch = context.packageManager.getLaunchIntentForPackage(pkg) ?: error("no launcher activity")
        context.startActivity(launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
        // The UI process reports its probes from Application.onCreate.
        val report = CoreStub.reports.poll(60, TimeUnit.SECONDS)
        assertNotNull("no report from the UI process in $mode", report)
        val result = JSONObject(report!!)

        // Wait for the screen; UiAutomator finds it through the accessibility tree.
        val input = device.wait(Until.findObject(By.res("input")), 30_000)
        result.put("accessible", input != null)
        if (input != null) drive(result)

        Log.i(TAG, "RESULT $result")
        return result
    }

    /** The interactions a chat UI needs, recorded into [result]. */
    private fun drive(result: JSONObject) {
        // Soft keyboard: focus the field, then ask the input method service whether it is shown.
        device.findObject(By.res("input")).click()
        device.waitForIdle()
        Thread.sleep(1500)
        val ime = device.executeShellCommand("dumpsys input_method")
        result.put("ime_shown", ime.contains("mInputShown=true") || ime.contains("isInputViewShown=true"))

        // Key events through the input pipeline into the focused field.
        device.executeShellCommand("input text mesh")
        result.put("typed_text", device.wait(Until.hasObject(By.textContains("mesh")), 5_000))

        // Accessibility text entry and a round trip to the core.
        device.findObject(By.res("input")).text = "hello core"
        device.findObject(By.res("send")).click()
        result.put("echo_round_trip", device.wait(Until.hasObject(By.text("echo: hello core")), 10_000))

        // Scrolling and frame timing, read from the UI process's graphics stats.
        // gfxinfo matches a package name only against the process of exactly
        // that name (the core here), so the `:ui` process is named by pid.
        device.pressBack()
        val ui = ui_pid()
        device.executeShellCommand("dumpsys gfxinfo $ui reset")
        val list = device.findObject(By.res("list"))
        repeat(5) { list?.fling(Direction.DOWN) }
        repeat(5) { list?.fling(Direction.UP) }
        result.put("gfxinfo", frame_stats(device.executeShellCommand("dumpsys gfxinfo $ui")))

        // Rotation recreates the Activity in the same, still confined, process.
        val pid = ui_pid()
        device.setOrientationLeft()
        val rotated = device.wait(Until.findObject(By.res("input")), 10_000) != null
        device.setOrientationNatural()
        device.wait(Until.findObject(By.res("input")), 10_000)
        result.put("survived_rotation", rotated && ui_pid() == pid)
    }

    /** The headline numbers from `dumpsys gfxinfo <pid>`. */
    private fun frame_stats(dump: String): JSONObject {
        val stats = JSONObject()
        Regex("""(Total frames rendered|Janky frames|50th percentile|90th percentile|95th percentile|99th percentile): ([^\n]+)""")
            .findAll(dump).forEach { stats.put(it.groupValues[1], it.groupValues[2].trim()) }
        return stats
    }

    /** The running `:ui` process's pid, or 0. */
    private fun ui_pid(): Int = context.getSystemService(ActivityManager::class.java)
        .runningAppProcesses?.firstOrNull { it.processName == "$pkg:ui" }?.pid ?: 0

    /** Ends any running UI process, so the next launch attaches afresh. */
    private fun kill_ui() {
        val pid = ui_pid()
        if (pid == 0) return
        Process.killProcess(pid)
        // Wait until the system has noticed.
        repeat(50) {
            if (ui_pid() == 0) return
            Thread.sleep(100)
        }
    }

    companion object {
        private const val TAG = "MeshUiSpike"
    }
}
