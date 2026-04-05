package com.oniimediaworks.meshinfinity

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.NetworkInfo
import android.net.wifi.WpsInfo
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pDevice
import android.net.wifi.p2p.WifiP2pDeviceList
import android.net.wifi.p2p.WifiP2pInfo
import android.net.wifi.p2p.WifiP2pManager
import android.nfc.NdefMessage
import android.nfc.NdefRecord
import android.nfc.NfcAdapter
import android.os.Build
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import io.flutter.embedding.android.FlutterActivity
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class AndroidProximityBridge(
    private val activity: FlutterActivity,
    messenger: BinaryMessenger
) : MethodChannel.MethodCallHandler, EventChannel.StreamHandler {
    companion object {
        private const val METHOD_CHANNEL = "mesh_infinity/android_proximity"
        private const val EVENT_CHANNEL = "mesh_infinity/android_proximity_events"
        private const val NFC_EXTERNAL_TYPE = "meshinfinity.io:pairing"
        private const val WIFI_DIRECT_PAIRING_PORT = 37129
    }

    private val applicationContext: Context = activity.applicationContext
    private val methodChannel = MethodChannel(messenger, METHOD_CHANNEL)
    private val eventChannel = EventChannel(messenger, EVENT_CHANNEL)
    private val wifiP2pManager =
        applicationContext.getSystemService(Context.WIFI_P2P_SERVICE) as? WifiP2pManager
    private val wifiP2pChannel =
        wifiP2pManager?.initialize(applicationContext, activity.mainLooper, null)
    private val nfcAdapter: NfcAdapter? = NfcAdapter.getDefaultAdapter(applicationContext)
    private var eventSink: EventChannel.EventSink? = null
    private var wifiReceiverRegistered = false
    private var wifiDiscoveryActive = false
    private var wifiP2pEnabled = false
    private var wifiConnected = false
    private var wifiPeers: List<Map<String, Any?>> = emptyList()
    private var wifiConnectionRole: String? = null
    private var wifiGroupOwnerAddress: String? = null
    private var wifiConnectedDeviceAddress: String? = null
    private var wifiPairingServer: ServerSocket? = null
    private var pendingWifiPermissionResult: MethodChannel.Result? = null
    private val ioExecutor: ExecutorService = Executors.newSingleThreadExecutor()
    private val wifiPermissionLauncher =
        activity.registerForActivityResult(
            ActivityResultContracts.RequestMultiplePermissions()
        ) { grants ->
            val granted = grants.values.all { it }
            pendingWifiPermissionResult?.success(granted)
            pendingWifiPermissionResult = null
            emitWifiState()
        }

    private val wifiReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION -> {
                    val state = intent.getIntExtra(
                        WifiP2pManager.EXTRA_WIFI_STATE,
                        WifiP2pManager.WIFI_P2P_STATE_DISABLED
                    )
                    wifiP2pEnabled = state == WifiP2pManager.WIFI_P2P_STATE_ENABLED
                    emitWifiState()
                }

                WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION -> {
                    requestPeers()
                }

                WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION -> {
                    val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        intent.getParcelableExtra(
                            WifiP2pManager.EXTRA_NETWORK_INFO,
                            NetworkInfo::class.java
                        )
                    } else {
                        @Suppress("DEPRECATION")
                        intent.getParcelableExtra(WifiP2pManager.EXTRA_NETWORK_INFO)
                    }
                    wifiConnected = info?.isConnected == true
                    requestConnectionInfo()
                    emitWifiState()
                }
            }
        }
    }

    init {
        methodChannel.setMethodCallHandler(this)
        eventChannel.setStreamHandler(this)
        wifiP2pEnabled = wifiP2pManager != null
        handleIntent(activity.intent)
    }

    fun dispose() {
        methodChannel.setMethodCallHandler(null)
        eventChannel.setStreamHandler(null)
        closeWifiPairingServer()
        ioExecutor.shutdownNow()
        unregisterWifiReceiver()
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "getCapabilities" -> result.success(buildCapabilities())
            "requestWifiDirectPermission" -> requestWifiDirectPermission(result)
            "startWifiDirectDiscovery" -> startWifiDirectDiscovery(result)
            "stopWifiDirectDiscovery" -> stopWifiDirectDiscovery(result)
            "connectWifiDirectPeer" -> connectWifiDirectPeer(call, result)
            "disconnectWifiDirectPeer" -> disconnectWifiDirectPeer(result)
            "exchangeWifiDirectPairingPayload" -> exchangeWifiDirectPairingPayload(call, result)
            "exchangeWifiDirectSessionFrame" -> exchangeWifiDirectSessionFrame(call, result)
            "getWifiDirectPeers" -> result.success(wifiPeers)
            else -> result.notImplemented()
        }
    }

    override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
        eventSink = events
        emitWifiState()
    }

    override fun onCancel(arguments: Any?) {
        eventSink = null
    }

    fun handleIntent(intent: Intent?): Boolean {
        if (intent == null) {
            return false
        }
        val action = intent.action ?: return false
        if (
            action != NfcAdapter.ACTION_NDEF_DISCOVERED &&
                action != NfcAdapter.ACTION_TAG_DISCOVERED &&
                action != NfcAdapter.ACTION_TECH_DISCOVERED
        ) {
            return false
        }
        val messages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableArrayExtra(
                NfcAdapter.EXTRA_NDEF_MESSAGES,
                NdefMessage::class.java
            )
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableArrayExtra(NfcAdapter.EXTRA_NDEF_MESSAGES)
        } ?: return false

        var delivered = false
        for (rawMessage in messages) {
            val message = rawMessage as? NdefMessage ?: continue
            for (record in message.records) {
                val payload = parsePairingPayload(record) ?: continue
                eventSink?.success(
                    mapOf(
                        "type" to "nfcPairingPayload",
                        "payloadJson" to payload,
                    )
                )
                delivered = true
            }
        }
        if (delivered) {
            activity.intent = Intent(activity.intent).apply {
                action = Intent.ACTION_MAIN
            }
        }
        return delivered
    }

    private fun buildCapabilities(): Map<String, Any?> {
        return mapOf(
            "isAndroid" to true,
            "nfcAvailable" to (nfcAdapter != null),
            "nfcEnabled" to (nfcAdapter?.isEnabled == true),
            "wifiDirectAvailable" to (wifiP2pManager != null),
            "wifiDirectEnabled" to wifiP2pEnabled,
            "wifiDirectPermissionGranted" to hasWifiDirectPermission(),
            "wifiDirectDiscoveryActive" to wifiDiscoveryActive,
            "wifiDirectConnected" to wifiConnected,
            "wifiDirectConnectionRole" to wifiConnectionRole,
            "wifiDirectGroupOwnerAddress" to wifiGroupOwnerAddress,
            "wifiDirectConnectedDeviceAddress" to wifiConnectedDeviceAddress,
        )
    }

    private fun requestWifiDirectPermission(result: MethodChannel.Result) {
        if (hasWifiDirectPermission()) {
            result.success(true)
            return
        }
        if (pendingWifiPermissionResult != null) {
            result.error("busy", "WiFi Direct permission request already in progress", null)
            return
        }
        pendingWifiPermissionResult = result
        val permissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            arrayOf(Manifest.permission.NEARBY_WIFI_DEVICES)
        } else {
            arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }
        wifiPermissionLauncher.launch(permissions)
    }

    private fun startWifiDirectDiscovery(result: MethodChannel.Result) {
        val manager = wifiP2pManager
        val channel = wifiP2pChannel
        if (manager == null || channel == null) {
            result.error("not_available", "WiFi Direct is not available", null)
            return
        }
        if (!hasWifiDirectPermission()) {
            result.error("permission_denied", "WiFi Direct permission not granted", null)
            return
        }
        registerWifiReceiver()
        manager.discoverPeers(
            channel,
            object : WifiP2pManager.ActionListener {
                override fun onSuccess() {
                    wifiDiscoveryActive = true
                    requestPeers()
                    emitWifiState()
                    result.success(true)
                }

                override fun onFailure(reason: Int) {
                    result.error("discover_failed", "WiFi Direct discovery failed: $reason", null)
                }
            }
        )
    }

    private fun stopWifiDirectDiscovery(result: MethodChannel.Result) {
        val manager = wifiP2pManager
        val channel = wifiP2pChannel
        if (manager == null || channel == null) {
            result.success(false)
            return
        }
        manager.stopPeerDiscovery(
            channel,
            object : WifiP2pManager.ActionListener {
                override fun onSuccess() {
                    wifiDiscoveryActive = false
                    wifiPeers = emptyList()
                    emitWifiState()
                    unregisterWifiReceiver()
                    result.success(true)
                }

                override fun onFailure(reason: Int) {
                    result.error("stop_failed", "WiFi Direct stop failed: $reason", null)
                }
            }
        )
    }

    private fun connectWifiDirectPeer(call: MethodCall, result: MethodChannel.Result) {
        val manager = wifiP2pManager
        val channel = wifiP2pChannel
        if (manager == null || channel == null) {
            result.error("not_available", "WiFi Direct is not available", null)
            return
        }
        if (!hasWifiDirectPermission()) {
            result.error("permission_denied", "WiFi Direct permission not granted", null)
            return
        }
        val deviceAddress = call.argument<String>("deviceAddress")?.takeIf { it.isNotBlank() }
        if (deviceAddress == null) {
            result.error("invalid_args", "Missing deviceAddress", null)
            return
        }
        registerWifiReceiver()
        val config = WifiP2pConfig().apply {
            this.deviceAddress = deviceAddress
            wps.setup = WpsInfo.PBC
        }
        manager.connect(
            channel,
            config,
            object : WifiP2pManager.ActionListener {
                override fun onSuccess() {
                    wifiConnectedDeviceAddress = deviceAddress
                    emitWifiState()
                    result.success(true)
                }

                override fun onFailure(reason: Int) {
                    result.error("connect_failed", "WiFi Direct connect failed: $reason", null)
                }
            }
        )
    }

    private fun disconnectWifiDirectPeer(result: MethodChannel.Result) {
        val manager = wifiP2pManager
        val channel = wifiP2pChannel
        if (manager == null || channel == null) {
            result.success(false)
            return
        }
        manager.removeGroup(
            channel,
            object : WifiP2pManager.ActionListener {
                override fun onSuccess() {
                    wifiConnected = false
                    wifiConnectionRole = null
                    wifiGroupOwnerAddress = null
                    wifiConnectedDeviceAddress = null
                    closeWifiPairingServer()
                    emitWifiState()
                    result.success(true)
                }

                override fun onFailure(reason: Int) {
                    result.error("disconnect_failed", "WiFi Direct disconnect failed: $reason", null)
                }
            }
        )
    }

    private fun requestPeers() {
        val manager = wifiP2pManager ?: return
        val channel = wifiP2pChannel ?: return
        if (!hasWifiDirectPermission()) {
            return
        }
        manager.requestPeers(channel) { peers: WifiP2pDeviceList ->
            wifiPeers = peers.deviceList.map(::mapWifiPeer)
            eventSink?.success(
                mapOf(
                    "type" to "wifiDirectPeersChanged",
                    "peers" to wifiPeers,
                )
            )
        }
    }

    private fun requestConnectionInfo() {
        val manager = wifiP2pManager ?: return
        val channel = wifiP2pChannel ?: return
        if (!hasWifiDirectPermission()) {
            return
        }
        manager.requestConnectionInfo(channel) { info: WifiP2pInfo? ->
            if (info == null) {
                wifiConnectionRole = null
                wifiGroupOwnerAddress = null
                closeWifiPairingServer()
            } else {
                wifiConnectionRole = when {
                    info.groupFormed && info.isGroupOwner -> "group_owner"
                    info.groupFormed -> "client"
                    else -> null
                }
                wifiGroupOwnerAddress = info.groupOwnerAddress?.hostAddress
            }
            emitWifiState()
        }
    }

    private fun exchangeWifiDirectPairingPayload(
        call: MethodCall,
        result: MethodChannel.Result
    ) {
        if (!wifiConnected) {
            result.error("not_connected", "WiFi Direct session is not connected", null)
            return
        }
        val payloadJson = call.argument<String>("payloadJson")?.takeIf { it.isNotBlank() }
        if (payloadJson == null) {
            result.error("invalid_args", "Missing payloadJson", null)
            return
        }
        when (wifiConnectionRole) {
            "group_owner" -> startWifiPairingServer(payloadJson, result)
            "client" -> connectWifiPairingClient(payloadJson, result)
            else -> result.error(
                "not_ready",
                "WiFi Direct role is not established yet",
                null
            )
        }
    }

    private fun exchangeWifiDirectSessionFrame(
        call: MethodCall,
        result: MethodChannel.Result
    ) {
        if (!wifiConnected) {
            result.error("not_connected", "WiFi Direct session is not connected", null)
            return
        }
        val frameHex = call.argument<String>("frameHex")?.takeIf { it.isNotBlank() }
        if (frameHex == null) {
            result.error("invalid_args", "Missing frameHex", null)
            return
        }
        val frameBytes =
            try {
                hexToBytes(frameHex)
            } catch (e: IllegalArgumentException) {
                result.error("invalid_args", "Invalid frameHex: ${e.message}", null)
                return
            }
        when (wifiConnectionRole) {
            "group_owner" -> startWifiSessionServer(frameBytes, result)
            "client" -> connectWifiSessionClient(frameBytes, result)
            else -> result.error(
                "not_ready",
                "WiFi Direct role is not established yet",
                null
            )
        }
    }

    private fun startWifiPairingServer(payloadJson: String, result: MethodChannel.Result) {
        closeWifiPairingServer()
        ioExecutor.execute {
            var started = false
            try {
                val server = ServerSocket(WIFI_DIRECT_PAIRING_PORT)
                wifiPairingServer = server
                started = true
                activity.runOnUiThread { result.success(true) }
                server.use { listener ->
                    val socket = listener.accept()
                    handleWifiPairingSocket(socket, payloadJson)
                }
            } catch (e: Exception) {
                closeWifiPairingServer()
                if (!started) {
                    activity.runOnUiThread {
                        result.error(
                            "exchange_failed",
                            "WiFi Direct pairing server failed: ${e.message}",
                            null
                        )
                    }
                }
            } finally {
                closeWifiPairingServer()
            }
        }
    }

    private fun connectWifiPairingClient(payloadJson: String, result: MethodChannel.Result) {
        val host = wifiGroupOwnerAddress?.takeIf { it.isNotBlank() }
        if (host == null) {
            result.error(
                "not_ready",
                "WiFi Direct group owner address is not available",
                null
            )
            return
        }
        ioExecutor.execute {
            try {
                Socket(host, WIFI_DIRECT_PAIRING_PORT).use { socket ->
                    handleWifiPairingSocket(socket, payloadJson)
                }
                activity.runOnUiThread { result.success(true) }
            } catch (e: Exception) {
                activity.runOnUiThread {
                    result.error(
                        "exchange_failed",
                        "WiFi Direct pairing exchange failed: ${e.message}",
                        null
                    )
                }
            }
        }
    }

    private fun startWifiSessionServer(frameBytes: ByteArray, result: MethodChannel.Result) {
        closeWifiPairingServer()
        ioExecutor.execute {
            var started = false
            try {
                val server = ServerSocket(WIFI_DIRECT_PAIRING_PORT)
                wifiPairingServer = server
                started = true
                activity.runOnUiThread { result.success(true) }
                server.use { listener ->
                    val socket = listener.accept()
                    handleWifiSessionSocket(socket, frameBytes)
                }
            } catch (e: Exception) {
                closeWifiPairingServer()
                if (!started) {
                    activity.runOnUiThread {
                        result.error(
                            "exchange_failed",
                            "WiFi Direct session server failed: ${e.message}",
                            null
                        )
                    }
                }
            } finally {
                closeWifiPairingServer()
            }
        }
    }

    private fun connectWifiSessionClient(frameBytes: ByteArray, result: MethodChannel.Result) {
        val host = wifiGroupOwnerAddress?.takeIf { it.isNotBlank() }
        if (host == null) {
            result.error(
                "not_ready",
                "WiFi Direct group owner address is not available",
                null
            )
            return
        }
        ioExecutor.execute {
            try {
                Socket(host, WIFI_DIRECT_PAIRING_PORT).use { socket ->
                    handleWifiSessionSocket(socket, frameBytes)
                }
                activity.runOnUiThread { result.success(true) }
            } catch (e: Exception) {
                activity.runOnUiThread {
                    result.error(
                        "exchange_failed",
                        "WiFi Direct session exchange failed: ${e.message}",
                        null
                    )
                }
            }
        }
    }

    private fun handleWifiPairingSocket(socket: Socket, payloadJson: String) {
        socket.soTimeout = 10_000
        val output = DataOutputStream(BufferedOutputStream(socket.getOutputStream()))
        val input = DataInputStream(BufferedInputStream(socket.getInputStream()))
        val outbound = payloadJson.toByteArray(StandardCharsets.UTF_8)
        output.writeInt(outbound.size)
        output.write(outbound)
        output.flush()
        val inboundLength = input.readInt()
        if (inboundLength <= 0 || inboundLength > 64 * 1024) {
            throw IllegalStateException("WiFi Direct pairing payload length is invalid")
        }
        val inbound = ByteArray(inboundLength)
        input.readFully(inbound)
        emitPairingPayloadEvent(
            String(inbound, StandardCharsets.UTF_8),
            "wifiDirectPairingPayload"
        )
    }

    private fun handleWifiSessionSocket(socket: Socket, frameBytes: ByteArray) {
        socket.soTimeout = 10_000
        val output = DataOutputStream(BufferedOutputStream(socket.getOutputStream()))
        val input = DataInputStream(BufferedInputStream(socket.getInputStream()))
        output.writeInt(frameBytes.size)
        output.write(frameBytes)
        output.flush()
        val inboundLength = input.readInt()
        if (inboundLength <= 0 || inboundLength > 256 * 1024) {
            throw IllegalStateException("WiFi Direct session frame length is invalid")
        }
        val inbound = ByteArray(inboundLength)
        input.readFully(inbound)
        activity.runOnUiThread {
            eventSink?.success(
                mapOf(
                    "type" to "wifiDirectSessionFrame",
                    "frameHex" to bytesToHex(inbound),
                )
            )
        }
    }

    private fun emitPairingPayloadEvent(payloadJson: String, type: String) {
        activity.runOnUiThread {
            eventSink?.success(
                mapOf(
                    "type" to type,
                    "payloadJson" to payloadJson,
                )
            )
        }
    }

    private fun closeWifiPairingServer() {
        try {
            wifiPairingServer?.close()
        } catch (_: Exception) {
        } finally {
            wifiPairingServer = null
        }
    }

    private fun emitWifiState() {
        eventSink?.success(
            mapOf(
                "type" to "wifiDirectStateChanged",
                "capabilities" to buildCapabilities(),
                "peers" to wifiPeers,
            )
        )
    }

    private fun hexToBytes(value: String): ByteArray {
        require(value.length % 2 == 0) { "hex length must be even" }
        return ByteArray(value.length / 2) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    private fun bytesToHex(bytes: ByteArray): String {
        val out = StringBuilder(bytes.size * 2)
        for (byte in bytes) {
            out.append(String.format("%02x", byte.toInt() and 0xff))
        }
        return out.toString()
    }

    private fun mapWifiPeer(device: WifiP2pDevice): Map<String, Any?> {
        val status = when (device.status) {
            WifiP2pDevice.AVAILABLE -> "available"
            WifiP2pDevice.INVITED -> "invited"
            WifiP2pDevice.CONNECTED -> "connected"
            WifiP2pDevice.FAILED -> "failed"
            WifiP2pDevice.UNAVAILABLE -> "unavailable"
            else -> "unknown"
        }
        return mapOf(
            "deviceName" to device.deviceName,
            "deviceAddress" to device.deviceAddress,
            "status" to status,
            "primaryDeviceType" to device.primaryDeviceType,
            "secondaryDeviceType" to device.secondaryDeviceType,
            "isGroupOwner" to device.isGroupOwner,
        )
    }

    private fun parsePairingPayload(record: NdefRecord): String? {
        if (record.tnf != NdefRecord.TNF_EXTERNAL_TYPE) {
            return null
        }
        val type = String(record.type, StandardCharsets.UTF_8)
        if (type != NFC_EXTERNAL_TYPE) {
            return null
        }
        return try {
            String(record.payload, StandardCharsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }

    private fun hasWifiDirectPermission(): Boolean {
        val permission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            Manifest.permission.NEARBY_WIFI_DEVICES
        } else {
            Manifest.permission.ACCESS_FINE_LOCATION
        }
        return ContextCompat.checkSelfPermission(applicationContext, permission) ==
            PackageManager.PERMISSION_GRANTED
    }

    private fun registerWifiReceiver() {
        if (wifiReceiverRegistered) {
            return
        }
        val filter = IntentFilter().apply {
            addAction(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION)
        }
        activity.registerReceiver(wifiReceiver, filter)
        wifiReceiverRegistered = true
    }

    private fun unregisterWifiReceiver() {
        if (!wifiReceiverRegistered) {
            return
        }
        activity.unregisterReceiver(wifiReceiver)
        wifiReceiverRegistered = false
    }
}
