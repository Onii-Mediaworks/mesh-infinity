package com.oniimediaworks.meshinfinity.uispike.flutter

import com.oniimediaworks.meshinfinity.uispike.UiSession
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * The Flutter host's UI, in the `:ui` process. By the time this Activity
 * starts, Application.onCreate has already locked the process down
 * (UiSession), so the Flutter engine and Dart run confined from their
 * first instruction. Dart talks to the core only through this channel.
 */
class MainActivity : FlutterActivity() {
    override fun configureFlutterEngine(engine: FlutterEngine) {
        super.configureFlutterEngine(engine)
        MethodChannel(engine.dartExecutor.binaryMessenger, "mesh_ui_spike/core").setMethodCallHandler { call, result ->
            when (call.method) {
                "status" -> result.success(
                    "mode ${UiSession.mode}, confined ${UiSession.confined}\n" +
                        UiSession.probes.entries.joinToString("\n") { (name, value) ->
                            "$name: " + if (value == 0) "ALLOWED" else "refused ($value)"
                        },
                )
                "request" -> result.success(UiSession.request(call.arguments as? String ?: ""))
                else -> result.notImplemented()
            }
        }
    }
}
