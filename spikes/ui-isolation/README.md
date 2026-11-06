# UI isolation spikes (Phase 0)

These are throwaway experiments for the UI process split and the move to Compose Multiplatform. Each one answers a single go/no-go question before Phase 1 begins. They live on the `spike/ui-isolation` branch only and are never merged into `main`.

| Spike | Question | Where |
|---|---|---|
| S1 | Can a Compose UI run in its own `:ui` Android process, locked down by Fibrewall, and still work as well as an unconfined one? Covers GPU rendering, the soft keyboard, accessibility, rotation and scrolling. | `android/`, CI job `s1-android-*` |
| S2 | Linux: the Flutter GTK runner and Compose desktop under Fibrewall | planned |
| S3 | Windows: Flutter and Compose desktop under Fibrewall `sbx_spawn` (AppContainer) | planned |
| S4 | macOS: App Sandbox helper, inherited socket, code-signing peer check | planned |
| S5 | Protocol Buffers round trip across Rust, Dart and Kotlin, plus a fuzz harness | planned |

Fibrewall is pinned at v0.6.1 as the `vendor/fibrewall` submodule.

## S1 at a glance

The app has three processes, the worker model from plan §3.0:
- The **main process** is a stand-in for the core. It writes a "secret" into `filesDir`, answers the UI over a socket (`CoreStub.kt`), and grants the UI's policy (`UiPolicy.kt`) when the warden asks for it. No Fibrewall code runs in the main process.
- The **`:warden` process** runs the Fibrewall broker under the policy the core granted (`WardenProvider.kt`). It holds no secrets.
- The **`:ui` process** starts in `Application.onCreate`. It hands its protocol socket to the core and its broker socket to the warden. Then, depending on the run's mode, it locks itself down (`UiSession.kt`). Next it tries to escape: it reads the core's secret, opens the core's and the warden's `/proc` memory files, opens a network socket, uses `ptrace` on both, sends a signal and runs `execve`. It reports the results to the core.

The instrumented test (`UiIsolationSpikeTest.kt`) starts the UI three times:
1. **off:** the unconfined baseline;
2. **learn:** locked down, but nothing is refused; every refusal it would have made is logged as `MeshUiBroker LEARNED ...`;
3. **enforce:** locked down under the policy.

On each run it types through the soft keyboard and through accessibility, sends a message to the core and back, scrolls, rotates the device, and logs one `MeshUiSpike RESULT {...}` line.

**Gates (all under enforce):**
- the lockdown succeeds;
- every escape probe is refused;
- the core still answers;
- the soft keyboard, typing, the round trip and rotation behave exactly as they do in the baseline.

Frame statistics are recorded for comparison but are not a gate.

**Results:** each emulator job uploads `spike-log.txt` (the RESULT lines and the broker records), the full `logcat.txt`, and the test report. The `s1-android-apks` artifact holds the APKs for installing on a real arm64 device.

On spike branches only, `build.yml` skips `spike/**`, so only this workflow runs.
