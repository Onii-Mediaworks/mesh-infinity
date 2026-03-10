package com.oniimediaworks.meshinfinity

import io.flutter.embedding.android.FlutterActivity

class MainActivity : FlutterActivity() {
    companion object {
        init {
            System.loadLibrary("mesh_infinity")
        }

        @JvmStatic
        private external fun nativeSetConfigDir(path: String): Int
    }

    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        val configDir = applicationContext.filesDir.resolve("mesh-infinity")
        nativeSetConfigDir(configDir.absolutePath)
        super.onCreate(savedInstanceState)
    }
}
