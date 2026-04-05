package com.oniimediaworks.meshinfinity

import android.content.Intent
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine

class MainActivity : FlutterActivity() {
    private var androidProximityBridge: AndroidProximityBridge? = null
    private var androidKeystoreChannel: AndroidKeystoreChannel? = null
    private var androidVpnChannel: AndroidVpnChannel? = null
    private var androidAppCatalogChannel: AndroidAppCatalogChannel? = null
    private var androidStartupChannel: AndroidStartupChannel? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        androidKeystoreChannel =
            AndroidKeystoreChannel(flutterEngine.dartExecutor.binaryMessenger)
        androidVpnChannel =
            AndroidVpnChannel(this, flutterEngine.dartExecutor.binaryMessenger)
        androidAppCatalogChannel =
            AndroidAppCatalogChannel(this, flutterEngine.dartExecutor.binaryMessenger)
        androidStartupChannel =
            AndroidStartupChannel(this, flutterEngine.dartExecutor.binaryMessenger)
        androidProximityBridge =
            AndroidProximityBridge(this, flutterEngine.dartExecutor.binaryMessenger)
        androidProximityBridge?.handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        androidProximityBridge?.handleIntent(intent)
    }

    override fun onDestroy() {
        androidProximityBridge?.dispose()
        androidProximityBridge = null
        androidKeystoreChannel?.dispose()
        androidKeystoreChannel = null
        androidVpnChannel?.dispose()
        androidVpnChannel = null
        androidAppCatalogChannel?.dispose()
        androidAppCatalogChannel = null
        androidStartupChannel?.dispose()
        androidStartupChannel = null
        super.onDestroy()
    }
}
