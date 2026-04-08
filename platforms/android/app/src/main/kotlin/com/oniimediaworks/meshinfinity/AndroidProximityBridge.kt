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
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import android.os.ParcelFileDescriptor
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class AndroidProximityBridge(
    private val activity: MainActivity,
    messenger: BinaryMessenger
) : MethodChannel.MethodCallHandler, EventChannel.StreamHandler {
    companion object {
        private const val METHOD_CHANNEL = "mesh_infinity/android_proximity"
        private const val EVENT_CHANNEL = "mesh_infinity/android_proximity_events"
        private const val NFC_EXTERNAL_TYPE = "meshinfinity.io:pairing"
        private const val WIFI_DIRECT_PAIRING_PORT = 37129
        private const val WIFI_DIRECT_PERMISSION_REQUEST_CODE = 4101
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

    // Dedicated single-thread executor for the Wi-Fi Direct fd drain loop and
    // the NFC outbound drain loop.  Separate from ioExecutor so pairing I/O
    // and drain polling do not block each other.
    private val drainExecutor: ExecutorService = Executors.newCachedThreadPool()

    // Set to true while an NFC LLCP session is active so the outbound drain
    // loop knows whether to keep polling for frames to send.
    private val nfcSessionActive: AtomicBoolean = AtomicBoolean(false)

    // Buffer reused by the NFC drain loop.  Size matches NFC_MAX_FRAME_BYTES (244)
    // plus a small margin so oversized frames are never silently dropped.
    private val nfcDrainBuf: ByteArray = ByteArray(256)

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
        // Stop the NFC drain loop before shutting down the executor so the
        // loop thread can exit cleanly rather than being interrupted mid-write.
        stopNfcOutboundDrainLoop()
        ioExecutor.shutdownNow()
        drainExecutor.shutdownNow()
        unregisterWifiReceiver()
        pendingWifiPermissionResult = null
    }

    fun on_request_permissions_result(
        request_code: Int,
        grant_results: IntArray,
    ): Boolean {
        if (request_code != WIFI_DIRECT_PERMISSION_REQUEST_CODE) {
            return false
        }
        val granted = grant_results.isNotEmpty() &&
            grant_results.all { it == PackageManager.PERMISSION_GRANTED }
        pendingWifiPermissionResult?.success(granted)
        pendingWifiPermissionResult = null
        emitWifiState()
        return true
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
            activity.setIntent(Intent(activity.intent).apply {
                action = Intent.ACTION_MAIN
            })
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
        ActivityCompat.requestPermissions(
            activity,
            permissions,
            WIFI_DIRECT_PERMISSION_REQUEST_CODE,
        )
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
        // Capture peer MAC at call time so the fd-handoff lambda has a stable reference.
        val peerMac = wifiConnectedDeviceAddress ?: ""
        ioExecutor.execute {
            var started = false
            try {
                val server = ServerSocket(WIFI_DIRECT_PAIRING_PORT)
                wifiPairingServer = server
                started = true
                activity.runOnUiThread { result.success(true) }
                server.use { listener ->
                    val socket = listener.accept()
                    // Exchange the pairing payload first (this is the one-shot
                    // credential exchange; after it completes the socket is ready
                    // for ongoing session traffic).
                    handleWifiPairingSocket(socket, payloadJson)
                    // After the pairing exchange, transfer socket ownership to Rust.
                    // Rust will drive all subsequent send/receive for this peer.
                    // peerMac identifies the session in the Rust registry.
                    if (peerMac.isNotBlank()) {
                        handOffSocketToRust(socket, peerMac)
                    }
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
        val peerMac = wifiConnectedDeviceAddress ?: ""
        ioExecutor.execute {
            try {
                val socket = Socket(host, WIFI_DIRECT_PAIRING_PORT)
                handleWifiPairingSocket(socket, payloadJson)
                // Transfer socket ownership to Rust after the pairing exchange.
                if (peerMac.isNotBlank()) {
                    handOffSocketToRust(socket, peerMac)
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
        val peerMac = wifiConnectedDeviceAddress ?: ""
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
                    // Transfer socket ownership to Rust after the initial frame exchange.
                    if (peerMac.isNotBlank()) {
                        handOffSocketToRust(socket, peerMac)
                    }
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
        val peerMac = wifiConnectedDeviceAddress ?: ""
        ioExecutor.execute {
            try {
                val socket = Socket(host, WIFI_DIRECT_PAIRING_PORT)
                handleWifiSessionSocket(socket, frameBytes)
                // Transfer socket ownership to Rust after the initial frame exchange.
                if (peerMac.isNotBlank()) {
                    handOffSocketToRust(socket, peerMac)
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

    // -------------------------------------------------------------------------
    // Wi-Fi Direct fd handoff to Rust (§5.8 socket ownership transfer)
    // -------------------------------------------------------------------------
    //
    // After WifiP2pManager establishes a P2P group and the TCP socket is
    // connected (or accepted), this method detaches the file descriptor from
    // the JVM and hands it to Rust via mi_wifi_direct_session_fd.
    //
    // OWNERSHIP CONTRACT (critical — read before modifying):
    //
    //   1. We call ParcelFileDescriptor.fromSocket(socket).detachFd().
    //      detachFd() transfers ownership of the underlying OS file descriptor
    //      to the caller and marks the ParcelFileDescriptor as closed so the
    //      JVM's garbage collector will NOT call close(fd) when the object is
    //      finalized.
    //
    //   2. nativeWifiDirectSessionFd(ctxPtr, peerMac, fd) hands the raw fd to
    //      Rust, which wraps it in a TcpStream via from_raw_fd().  After this
    //      point Rust owns the fd exclusively.
    //
    //   3. We MUST NOT use `socket` or `fd` for any further I/O after step 2.
    //      The socket reference is abandoned; the JVM object is effectively dead.
    //
    //   4. We start drainWifiDirectSession() on drainExecutor.  This calls
    //      nativeWifiDirectDrainSession in a loop, which flushes Rust's outbound
    //      queue to the socket without re-entering the JVM for each frame.
    //
    // If the context pointer is 0 (backend not yet initialised) the handoff is
    // skipped and the socket remains Kotlin-managed for this session only.
    private fun handOffSocketToRust(socket: Socket, peerMac: String) {
        val ctxPtr = NativeLayer1Bridge.contextPointer
        if (ctxPtr == 0L) {
            // Backend not yet started — skip the fd handoff for this session.
            // The socket will be used via the existing frame-queue path instead.
            return
        }
        try {
            // detachFd() extracts the raw fd and severs the JVM's ownership.
            // After this call the JVM will NOT close the fd on GC.
            val pfd = ParcelFileDescriptor.fromSocket(socket)
            val fd = pfd.detachFd()
            // Hand the fd to Rust.  From this point on Rust owns the fd and
            // will close it when the session struct is dropped.
            val result = nativeWifiDirectSessionFd(ctxPtr, peerMac, fd)
            if (result != 0) {
                // Handoff failed (e.g. adapter not available).  The fd is now
                // in limbo — close it manually to avoid a leak.
                try {
                    android.system.Os.close(android.system.Os.open("/proc/self/fd/$fd", android.system.OsConstants.O_RDONLY, 0))
                } catch (_: Exception) {
                    // Best-effort close; ignore errors.
                }
                return
            }
            // Start the drain loop so Rust-authored frames reach the socket.
            startWifiDirectDrainLoop(peerMac)
        } catch (e: Exception) {
            // If detachFd or the JNI call fails we leave the socket in Kotlin's
            // hands.  The existing frame-queue bridge will continue to function.
        }
    }

    // Drain loop that flushes Rust's Wi-Fi Direct outbound queue to the fd-owned
    // socket.  Runs on drainExecutor (a separate thread from the UI thread).
    //
    // The loop terminates when:
    //   - nativeWifiDirectDrainSession returns < 0 (socket error), or
    //   - the Wi-Fi Direct session disconnects (wifiConnected becomes false).
    //
    // A 5 ms yield when no frames are pending keeps CPU impact negligible while
    // still flushing within one tick of a frame being queued by Rust.
    private fun startWifiDirectDrainLoop(peerMac: String) {
        drainExecutor.execute {
            val ctxPtr = NativeLayer1Bridge.contextPointer
            if (ctxPtr == 0L) return@execute
            while (wifiConnected) {
                val n = nativeWifiDirectDrainSession(ctxPtr, peerMac)
                when {
                    n < 0 -> break              // socket error — exit drain loop
                    n == 0 -> Thread.sleep(5)   // nothing to send — yield briefly
                    // n > 0 — frames were flushed; loop immediately for more
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // NFC outbound drain loop (§5.9 backend-driven send path)
    // -------------------------------------------------------------------------
    //
    // The NFC transport audit identified that the native bridge was not draining
    // backend-authored outbound frames.  This loop closes that gap.
    //
    // The loop calls mi_nfc_pop_outbound_frame in a tight poll and writes each
    // returned frame to the active LLCP connection via nfcLlcpWrite().
    //
    // Call startNfcOutboundDrainLoop() when an LLCP session is established.
    // Call stopNfcOutboundDrainLoop() when the session ends (tag out of range,
    // link dropped, etc.).
    //
    // The nfcSessionActive flag is the loop's stop signal.  Setting it to false
    // causes the loop to exit cleanly after its current iteration completes.
    fun startNfcOutboundDrainLoop(
        // Callback invoked for each outbound frame Rust produces.
        // The implementation should write `frameBytes` to the active LLCP link.
        // Returns true if the write succeeded, false otherwise (causes loop exit).
        onFrame: (frameBytes: ByteArray) -> Boolean,
    ) {
        nfcSessionActive.set(true)
        drainExecutor.execute {
            val ctxPtr = NativeLayer1Bridge.contextPointer
            if (ctxPtr == 0L) {
                nfcSessionActive.set(false)
                return@execute
            }
            while (nfcSessionActive.get()) {
                val n = nativeNfcPopOutboundFrame(ctxPtr, nfcDrainBuf, nfcDrainBuf.size)
                when {
                    n < 0 -> {
                        // Error from the backend (adapter gone, buffer too small, etc.).
                        nfcSessionActive.set(false)
                        break
                    }
                    n == 0 -> {
                        // Queue empty — yield for 5 ms before polling again.
                        // 5 ms is short enough to be imperceptible on any NFC exchange
                        // and avoids burning CPU in a tight spin while idle.
                        Thread.sleep(5)
                    }
                    else -> {
                        // n bytes were copied into nfcDrainBuf.  Hand a copy to the
                        // callback so the LLCP layer can transmit them.
                        val frame = nfcDrainBuf.copyOf(n)
                        val ok = onFrame(frame)
                        if (!ok) {
                            // Write failed — LLCP link is broken.  Stop the drain loop.
                            nfcSessionActive.set(false)
                            break
                        }
                    }
                }
            }
        }
    }

    // Stop the NFC outbound drain loop (e.g. when the NFC tag moves away or
    // the LLCP session is torn down).
    fun stopNfcOutboundDrainLoop() {
        nfcSessionActive.set(false)
    }

    // -------------------------------------------------------------------------
    // JNI declarations — new fd-session and NFC drain FFI functions
    // -------------------------------------------------------------------------
    //
    // These external functions map directly to Rust #[no_mangle] symbols in
    // backend/ffi/lib.rs.  The naming convention matches the JNI auto-generated
    // symbol for functions NOT declared as JNI functions — they are looked up
    // by symbol name via System.loadLibrary, so no package prefix is needed.
    //
    // mi_wifi_direct_session_fd:
    //   Accepts a detached socket fd and registers it as a Rust-owned session.
    //   Returns 0 on success, -1 on error.
    //
    // mi_wifi_direct_drain_session:
    //   Writes queued outbound frames to the Rust-owned session socket.
    //   Returns frame count (>= 0) or -1 on socket error.
    //
    // mi_nfc_pop_outbound_frame:
    //   Pops one Rust-authored NFC outbound frame into `buf`.
    //   Returns actual frame length, 0 if no frame pending, -1 on error.
    //
    // mi_nfc_push_inbound_frame:
    //   Pushes an inbound NFC frame (received from LLCP link or NDEF read)
    //   into the Rust backend's inbound queue.
    //   Returns 0 on success, -1 on error.
    //
    // Note: these symbols are only present in the Android build of the Rust
    // library (guarded by #[cfg(target_os = "android")] in Rust for the Wi-Fi
    // Direct functions; unconditional for the NFC functions).
    private external fun nativeWifiDirectSessionFd(
        ctxPtr: Long,
        peerMac: String,
        fd: Int,
    ): Int

    private external fun nativeWifiDirectDrainSession(
        ctxPtr: Long,
        peerMac: String,
    ): Int

    private external fun nativeNfcPopOutboundFrame(
        ctxPtr: Long,
        buf: ByteArray,
        bufLen: Int,
    ): Int

    private external fun nativeNfcPushInboundFrame(
        ctxPtr: Long,
        data: ByteArray,
        dataLen: Int,
    ): Int
}
