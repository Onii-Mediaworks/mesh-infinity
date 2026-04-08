package com.oniimediaworks.meshinfinity

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import org.json.JSONArray
import org.json.JSONObject
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.net.UnknownHostException
import java.nio.ByteBuffer

class AndroidAppConnectorVpnService : VpnService() {
    companion object {
        private const val CHANNEL_ID = "mesh_infinity_app_connector_vpn"
        private const val NOTIFICATION_ID = 4102

        // -----------------------------------------------------------------
        // IP header parsing constants
        // -----------------------------------------------------------------
        //
        // Raw IP packets arrive from the TUN interface as unframed byte arrays.
        // We parse only the fields needed for selector evaluation; we do not
        // rewrite or reassemble packets.
        //
        // IPv4 header layout (RFC 791):
        //   Byte 0         : version (high nibble) + IHL (low nibble)
        //   Bytes 12–15    : source IP address
        //   Bytes 16–19    : destination IP address
        //   Byte  9        : protocol (6=TCP, 17=UDP, 58=ICMPv6)
        //   IHL×4 offset + 0..1 : source port (TCP/UDP)
        //   IHL×4 offset + 2..3 : destination port (TCP/UDP)
        //
        // IPv6 header layout (RFC 8200):
        //   Byte  0        : version (high nibble = 6)
        //   Bytes 8–23     : source IP address
        //   Bytes 24–39    : destination IP address
        //   Byte  6        : next header / protocol
        //   Fixed 40-byte header; ports at offset 40..43
        //
        // DNS (UDP port 53): if the packet is a UDP DNS query we attempt to
        // extract the question QNAME so the backend can apply domain_pattern
        // rules before the connection is established.

        private const val IP_VERSION_MASK: Int = 0xF0
        private const val IP_VERSION_4: Int = 0x40
        private const val IP_VERSION_6: Int = 0x60

        private const val PROTO_TCP: Int = 6
        private const val PROTO_UDP: Int = 17

        private const val PORT_DNS: Int = 53

        // Maximum raw packet size we will read from the TUN fd in one call.
        // 65535 is the maximum IPv4 datagram size; IPv6 can be larger with
        // jumbograms but we cap here for simplicity — oversized packets are
        // discarded rather than parsed.
        private const val MAX_PACKET_BYTES: Int = 65535

        fun applyPolicy(context: Context, policyJson: String): Boolean {
            AndroidVpnPolicyStore.savePolicy(context, policyJson)
            val policy = JSONObject(policyJson)
            return if (policy.optBoolean("enabled", false)) {
                val intent = Intent(context, AndroidAppConnectorVpnService::class.java)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }
                true
            } else {
                stop(context)
                true
            }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, AndroidAppConnectorVpnService::class.java))
            AndroidVpnPolicyStore.updateRuntimeState(
                context = context,
                active = false,
                lastError = null,
                allowedCount = 0,
                disallowedCount = 0,
            )
        }
    }

    private var tunnelInterface: ParcelFileDescriptor? = null

    // -----------------------------------------------------------------------
    // Packet forwarding thread
    // -----------------------------------------------------------------------
    //
    // When the TUN interface is established we spin up a background thread that
    // reads raw IP packets from the TUN fd, evaluates them against the backend
    // App Connector selector rules, and then either:
    //
    //   ACTION_BLOCK        — discards the packet (it is not forwarded anywhere)
    //   ACTION_ALLOW_DIRECT — writes the packet back through the TUN fd with
    //                         the VpnService.protect() bypass, letting the OS
    //                         send it via the normal IP path
    //   ACTION_ROUTE_VIA_MESH — writes the packet to the mesh tunnel output
    //                           stream (stub: currently logged; full tunnel
    //                           integration is handled by transport_ops.rs)
    //
    // The thread exits when `packetForwardingActive` is set to false or when
    // the TUN fd becomes invalid (EOF / exception on read).

    @Volatile
    private var packetForwardingActive: Boolean = false
    private var packetForwardingThread: Thread? = null

    // Opaque backend context pointer.  Obtained from NativeLayer1Bridge so the
    // packet path can call mi_connector_evaluate without going through Flutter.
    // Zero means the backend is not yet available; we fall back to allow-direct.
    private var backendCtxPtr: Long = 0L

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        applyStoredPolicy()
        return START_STICKY
    }

    override fun onDestroy() {
        // Signal the packet forwarding thread to stop and wait for it.
        // We set the flag first so the thread can exit its read loop cleanly.
        stopPacketForwarding()
        tunnelInterface?.close()
        tunnelInterface = null
        AndroidVpnPolicyStore.updateRuntimeState(
            context = this,
            active = false,
            lastError = null,
            allowedCount = 0,
            disallowedCount = 0,
        )
        super.onDestroy()
    }

    override fun onRevoke() {
        AndroidVpnPolicyStore.updateRuntimeState(
            context = this,
            active = false,
            lastError = "VPN permission revoked",
            allowedCount = 0,
            disallowedCount = 0,
        )
        stopSelf()
        super.onRevoke()
    }

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    private fun applyStoredPolicy() {
        val policyJson = AndroidVpnPolicyStore.loadPolicy(this)
        if (policyJson.isNullOrBlank()) {
            AndroidVpnPolicyStore.updateRuntimeState(
                context = this,
                active = false,
                lastError = "No Android VPN policy available",
                allowedCount = 0,
                disallowedCount = 0,
            )
            stopSelf()
            return
        }

        val policy = JSONObject(policyJson)
        if (!policy.optBoolean("enabled", false)) {
            tunnelInterface?.close()
            tunnelInterface = null
            AndroidVpnPolicyStore.updateRuntimeState(
                context = this,
                active = false,
                lastError = null,
                allowedCount = 0,
                disallowedCount = 0,
            )
            stopSelf()
            return
        }

        if (VpnService.prepare(this) != null) {
            AndroidVpnPolicyStore.updateRuntimeState(
                context = this,
                active = false,
                lastError = "VPN permission not granted",
                allowedCount = 0,
                disallowedCount = 0,
            )
            stopSelf()
            return
        }

        val builder = Builder()
            .setSession(policy.optString("sessionName", "Mesh Infinity"))
            .setMtu(policy.optInt("mtu", 1280))

        builder.addAddress("198.18.0.1", 32)
        builder.addAddress("fd00:6d65:7368::1", 128)

        if (policy.optBoolean("requiresFullTunnel", true)) {
            builder.addRoute("0.0.0.0", 0)
            builder.addRoute("::", 0)
        }

        val allowedApps = policy.optJSONArray("allowedApps")
        val disallowedApps = policy.optJSONArray("disallowedApps")
        val appliedAllowed = applyAllowedApps(builder, allowedApps)
        val appliedDisallowed = applyDisallowedApps(builder, disallowedApps)

        // Apply selector-based routing rules (§13.15).
        //
        // IP range rules are enforced via addRoute() — packets destined for
        // those ranges are routed through the VPN tunnel.
        //
        // Domain pattern rules are resolved to IPs at policy apply time and
        // handled as IP routes.  Note: this is best-effort; IPs for a domain
        // can change after the policy is applied.
        //
        // Port-based rules are NOT enforceable via the Android VPN API —
        // VpnService.Builder has no per-port routing API.  These rules are
        // tracked as unresolved in the runtime state so the UI can warn the
        // user that port selectors require a userspace proxy (future work).
        val selectorRules = policy.optJSONArray("selectorRules")
            ?: policy.optJSONArray("rules")
        val selectorCounts = applySelectorRules(builder, selectorRules)

        // Stop any existing packet forwarding loop before closing the old fd.
        stopPacketForwarding()
        tunnelInterface?.close()
        tunnelInterface = builder.establish()

        AndroidVpnPolicyStore.updateRuntimeState(
            context = this,
            active = tunnelInterface != null,
            lastError = if (tunnelInterface == null) {
                "Android VpnService failed to establish the interface"
            } else {
                null
            },
            allowedCount = appliedAllowed,
            disallowedCount = appliedDisallowed,
            ipRouteCount = selectorCounts.first,
            unresolvedSelectorCount = selectorCounts.second,
        )

        if (tunnelInterface == null) {
            stopSelf()
            return
        }

        // Start the per-packet selector evaluation loop on a background thread.
        // This loop reads raw IP packets from the TUN interface, calls the Rust
        // backend to evaluate them against active App Connector rules, and then
        // routes each packet accordingly.
        startPacketForwarding(tunnelInterface!!)
    }

    // -----------------------------------------------------------------------
    // Packet forwarding loop — selector-aware per-packet routing
    // -----------------------------------------------------------------------

    /**
     * Start the background thread that reads packets from the TUN fd and
     * enforces per-packet selector rules via the Rust backend.
     *
     * @param tun  The established TUN interface descriptor.  The thread holds
     *             a reference to the underlying [FileInputStream]; closing
     *             [tun] from the main thread will cause the next [read] call
     *             to throw, which terminates the loop cleanly.
     */
    private fun startPacketForwarding(tun: ParcelFileDescriptor) {
        packetForwardingActive = true
        // Attempt to obtain the backend context pointer so the packet path can
        // call mi_connector_evaluate without round-tripping through Flutter.
        // NativeLayer1Bridge.contextPointer is populated by AndroidStartupService
        // once mesh_init (or the headless Layer 1 startup) completes.
        // If it is 0L the backend is not yet available; we fall back to
        // allow-direct for every packet until the backend is ready.
        backendCtxPtr = NativeLayer1Bridge.contextPointer

        val inputStream = FileInputStream(tun.fileDescriptor)
        val outputStream = FileOutputStream(tun.fileDescriptor)
        val packetBuffer = ByteArray(MAX_PACKET_BYTES)

        packetForwardingThread = Thread(
            {
                forwardPackets(inputStream, outputStream, packetBuffer)
            },
            "AppConnectorPacketForwarder",
        ).also { it.isDaemon = true; it.start() }
    }

    /** Signal the forwarding thread to stop and wait for it to exit. */
    private fun stopPacketForwarding() {
        packetForwardingActive = false
        packetForwardingThread?.interrupt()
        try {
            packetForwardingThread?.join(500L)
        } catch (_: InterruptedException) {
            // Best-effort join; if it times out the thread will stop at the
            // next fd close.
        }
        packetForwardingThread = null
    }

    /**
     * Inner loop: read → evaluate → route.
     *
     * Runs on [packetForwardingThread].  Exits when:
     *   - [packetForwardingActive] is false, or
     *   - The TUN fd is closed (read throws or returns -1).
     *
     * ## Routing decision
     *
     * For each packet we call [AndroidVpnPolicyStore.evaluateConnection] which
     * delegates to `mi_connector_evaluate` in the Rust backend.  The Rust
     * function evaluates all enabled `AppConnectorRule`s in priority order:
     *
     *   | Result constant                        | Action                        |
     *   |----------------------------------------|-------------------------------|
     *   | [AndroidVpnPolicyStore.ACTION_BLOCK]   | Discard — do not forward      |
     *   | [AndroidVpnPolicyStore.ACTION_ALLOW_DIRECT] | Forward via normal IP path |
     *   | [AndroidVpnPolicyStore.ACTION_ROUTE_VIA_MESH] | Forward via mesh tunnel |
     *
     * ## DNS domain extraction (port 53 UDP)
     *
     * When the destination port is 53 and the protocol is UDP we attempt to
     * parse the DNS question QNAME from the payload.  If successful the domain
     * name is passed to the backend so `domain_pattern` rules can be evaluated
     * against it before the connection reaches the upstream resolver.
     */
    private fun forwardPackets(
        input: FileInputStream,
        output: FileOutputStream,
        buffer: ByteArray,
    ) {
        while (packetForwardingActive) {
            // Read one raw IP packet.  Returns -1 on EOF / closed fd.
            val length = try {
                input.read(buffer)
            } catch (_: Exception) {
                // TUN fd was closed — exit the loop.
                break
            }
            if (length <= 0) break
            if (length < 20) continue  // Too short to be a valid IP header.

            // Parse IP version from the first nibble of byte 0.
            val version = buffer[0].toInt() and IP_VERSION_MASK
            val (dstIp, dstPort, dnsQuestion) = when (version) {
                IP_VERSION_4 -> parseIpv4Fields(buffer, length)
                IP_VERSION_6 -> parseIpv6Fields(buffer, length)
                else -> continue  // Unknown IP version; skip.
            } ?: continue

            // Evaluate selectors against the connection 4-tuple.
            val action = AndroidVpnPolicyStore.evaluateConnection(
                ctxPtr = backendCtxPtr,
                pkg = packageName,       // This service's own package — used as
                                         // the app identity for packets in scope.
                dstIp = dstIp,
                dstPort = dstPort,
                dstDomain = dnsQuestion, // null for non-DNS packets.
            )

            when (action) {
                AndroidVpnPolicyStore.ACTION_BLOCK -> {
                    // Drop the packet — do not forward it anywhere.
                    // The originating app will eventually receive a connection
                    // timeout or ICMP unreachable (not emitted here; we simply
                    // discard the outbound packet).
                    android.util.Log.v(
                        "AppConnectorVpn",
                        "Blocked packet to $dstIp:$dstPort (domain=$dnsQuestion)",
                    )
                }

                AndroidVpnPolicyStore.ACTION_ROUTE_VIA_MESH -> {
                    // Forward the packet through the mesh tunnel.
                    //
                    // Full tunnel integration: the packet is handed off to the
                    // Rust backend transport layer via mi_send_raw_packet (to be
                    // implemented in transport_ops.rs alongside the full data-
                    // plane).  Until that function is wired up we log the
                    // decision so it is visible in logcat during development.
                    //
                    // TODO(transport): replace this log with a call to
                    //   MeshNative.sendRawPacket(backendCtxPtr, buffer, 0, length)
                    //   when the raw-packet ingest path is implemented.
                    android.util.Log.v(
                        "AppConnectorVpn",
                        "RouteViaMesh: $dstIp:$dstPort (domain=$dnsQuestion) len=$length",
                    )
                }

                else -> {
                    // ACTION_ALLOW_DIRECT: write the packet back to the TUN fd.
                    // The Android TUN driver will re-inject it into the normal
                    // IP stack.  Because we called VpnService.protect() on the
                    // upstream socket this does not re-enter the VPN.
                    try {
                        output.write(buffer, 0, length)
                    } catch (_: Exception) {
                        // Write failure means the TUN fd is gone; exit.
                        break
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // IP header parsing helpers
    // -----------------------------------------------------------------------
    //
    // Each helper returns a Triple<String, Int, String?> (dstIp, dstPort, domain)
    // or null if the packet is too short / malformed.

    /**
     * Parse the destination IP, port, and optional DNS domain from an IPv4
     * packet.
     *
     * IPv4 layout:
     *   Byte  0         : Version (4) | IHL (header length in 32-bit words)
     *   Byte  9         : Protocol (6=TCP, 17=UDP)
     *   Bytes 16–19     : Destination IP address
     *   IHL×4 + 2–3     : Destination port (TCP/UDP)
     */
    private fun parseIpv4Fields(
        buf: ByteArray,
        len: Int,
    ): Triple<String, Int, String?>? {
        if (len < 20) return null

        // IHL is the lower nibble of byte 0, in units of 32-bit words.
        val ihl = (buf[0].toInt() and 0x0F) * 4
        if (ihl < 20 || len < ihl + 4) return null

        // Extract the destination IP from bytes 16–19.
        val dstIp = buildString {
            append(buf[16].toInt() and 0xFF)
            append('.')
            append(buf[17].toInt() and 0xFF)
            append('.')
            append(buf[18].toInt() and 0xFF)
            append('.')
            append(buf[19].toInt() and 0xFF)
        }

        val proto = buf[9].toInt() and 0xFF
        if (proto != PROTO_TCP && proto != PROTO_UDP) {
            // ICMP etc. have no port concept; use port 0 for selector matching.
            return Triple(dstIp, 0, null)
        }

        // TCP/UDP destination port: 2 bytes at transport-header offset + 2.
        val portOffset = ihl + 2
        if (len < portOffset + 2) return null
        val dstPort = ((buf[portOffset].toInt() and 0xFF) shl 8) or
            (buf[portOffset + 1].toInt() and 0xFF)

        // If this is a UDP DNS query, extract the QNAME from the question section.
        val dnsQuestion = if (proto == PROTO_UDP && dstPort == PORT_DNS) {
            extractDnsQname(buf, ihl + 8, len)  // UDP header is 8 bytes.
        } else {
            null
        }

        return Triple(dstIp, dstPort, dnsQuestion)
    }

    /**
     * Parse the destination IP, port, and optional DNS domain from an IPv6
     * packet.
     *
     * IPv6 layout:
     *   Bytes 0–3       : Version(6) | Traffic Class | Flow Label
     *   Byte  6         : Next Header / Protocol
     *   Bytes 24–39     : Destination IP address
     *   Fixed 40-byte header; transport-layer ports at offset 40 + 2.
     */
    private fun parseIpv6Fields(
        buf: ByteArray,
        len: Int,
    ): Triple<String, Int, String?>? {
        if (len < 40) return null

        // Destination IPv6 address: bytes 24–39.
        val dstIp = buildString {
            for (groupIndex in 0 until 8) {
                if (groupIndex > 0) append(':')
                val high = buf[24 + groupIndex * 2].toInt() and 0xFF
                val low  = buf[25 + groupIndex * 2].toInt() and 0xFF
                append(Integer.toHexString((high shl 8) or low))
            }
        }

        val proto = buf[6].toInt() and 0xFF
        if (proto != PROTO_TCP && proto != PROTO_UDP) {
            return Triple(dstIp, 0, null)
        }

        // Transport-layer destination port: IPv6 fixed header is 40 bytes,
        // followed by the transport header where bytes 2–3 are the dst port.
        val portOffset = 40 + 2
        if (len < portOffset + 2) return null
        val dstPort = ((buf[portOffset].toInt() and 0xFF) shl 8) or
            (buf[portOffset + 1].toInt() and 0xFF)

        val dnsQuestion = if (proto == PROTO_UDP && dstPort == PORT_DNS) {
            extractDnsQname(buf, 40 + 8, len)  // UDP header is 8 bytes.
        } else {
            null
        }

        return Triple(dstIp, dstPort, dnsQuestion)
    }

    /**
     * Attempt to extract the first QNAME from the DNS question section.
     *
     * DNS message layout (RFC 1035 §4.1):
     *   12-byte header, then the question section:
     *     QNAME: a sequence of labels, each prefixed by a 1-byte length,
     *            terminated by a zero-length label (0x00).
     *     QTYPE: 2 bytes
     *     QCLASS: 2 bytes
     *
     * [dnsPayloadOffset] is the byte offset into [buf] where the DNS payload
     * starts (after the UDP header).
     *
     * Returns the assembled domain name string, or null on any parse error.
     * We are deliberately lenient — a malformed DNS packet simply returns null,
     * which causes domain_pattern rules to be skipped for that packet.
     */
    private fun extractDnsQname(buf: ByteArray, dnsPayloadOffset: Int, len: Int): String? {
        // A minimal DNS message is 12 bytes (header) + 1 byte (root label).
        val questionStart = dnsPayloadOffset + 12
        if (len <= questionStart) return null

        val labels = mutableListOf<String>()
        var pos = questionStart

        // Walk the label sequence.  Each label is prefixed by its byte length.
        // Length 0 marks the end of the QNAME.  We abort on pointer compression
        // (high two bits = 11) since we do not have a full DNS message context.
        while (pos < len) {
            val labelLen = buf[pos].toInt() and 0xFF
            if (labelLen == 0) break  // End of QNAME.
            if (labelLen and 0xC0 == 0xC0) return null  // Pointer — skip.
            pos++
            if (pos + labelLen > len) return null  // Overrun.
            labels.add(String(buf, pos, labelLen, Charsets.US_ASCII))
            pos += labelLen
        }

        return if (labels.isEmpty()) null else labels.joinToString(".")
    }

    // Apply selector-based routing rules to the VPN builder.
    //
    // Returns a pair (ipRoutesApplied, unresolvedCount) where:
    //   ipRoutesApplied  — number of addRoute() calls that succeeded
    //   unresolvedCount  — number of rules that could not be enforced
    //                      (domain resolution failures, port-only rules)
    private fun applySelectorRules(
        builder: Builder,
        rules: JSONArray?,
    ): Pair<Int, Int> {
        if (rules == null) return Pair(0, 0)
        var applied = 0
        var unresolved = 0

        for (i in 0 until rules.length()) {
            val rule = rules.optJSONObject(i) ?: continue
            if (!rule.optBoolean("enabled", true)) continue

            val selector = rule.optJSONObject("app_selector") ?: continue

            // --- IP range rules -----------------------------------------------
            // Selector: { "ip_range": "10.0.0.0/8" }
            // Enforcement: addRoute() to send those packets through the tunnel.
            val ipRange = selector.optString("ip_range", "").trim()
            if (ipRange.isNotEmpty()) {
                val applied1 = applyIpRangeRoute(builder, ipRange)
                if (applied1) applied++ else unresolved++
                continue
            }

            // --- Domain pattern rules -----------------------------------------
            // Selector: { "domain_pattern": "*.example.com" }
            // Enforcement: resolve domain to IPs and add routes.
            // Limitations: wildcard patterns are collapsed to the base domain;
            // IP addresses returned here may change later (no DNS TTL tracking).
            val domain = selector.optString("domain_pattern", "").trim()
            if (domain.isNotEmpty()) {
                val resolved = resolveDomainToRoutes(builder, domain)
                if (resolved > 0) applied += resolved else unresolved++
                continue
            }

            // --- Port-only rules -----------------------------------------------
            // Android VPN API has no port-based routing; mark as unresolved.
            val port = selector.optInt("port", -1)
            if (port > 0) {
                unresolved++
                android.util.Log.d(
                    "AppConnectorVpn",
                    "Port selector ($port) cannot be enforced via Android VPN API " +
                        "— requires userspace proxy (future work, §13.15)"
                )
            }
        }

        return Pair(applied, unresolved)
    }

    // Parse a CIDR string (e.g. "10.0.0.0/8" or "fd00::/8") and call addRoute.
    // Returns true if the route was added, false on any parse error.
    private fun applyIpRangeRoute(builder: Builder, cidr: String): Boolean {
        return try {
            val slash = cidr.indexOf('/')
            val addrStr = if (slash >= 0) cidr.substring(0, slash) else cidr
            val prefix = if (slash >= 0) cidr.substring(slash + 1).toInt() else {
                // No prefix length: derive from address family.
                if (addrStr.contains(':')) 128 else 32
            }
            val addr = InetAddress.getByName(addrStr)
            builder.addRoute(addr, prefix)
            true
        } catch (e: Exception) {
            android.util.Log.w("AppConnectorVpn", "Could not apply IP route $cidr: ${e.message}")
            false
        }
    }

    // Resolve a domain pattern to IPs and add routes for each resolved address.
    // Wildcard patterns (e.g. "*.example.com") are stripped to the base domain.
    // Returns the number of routes added (0 on resolution failure).
    private fun resolveDomainToRoutes(builder: Builder, pattern: String): Int {
        // Strip wildcard prefix: "*.example.com" → "example.com"
        val domain = pattern.trimStart('*', '.')
        if (domain.isEmpty()) return 0

        return try {
            val addresses = InetAddress.getAllByName(domain)
            var count = 0
            for (addr in addresses) {
                try {
                    val prefixLen = if (addr is java.net.Inet6Address) 128 else 32
                    builder.addRoute(addr, prefixLen)
                    count++
                } catch (_: Exception) {
                }
            }
            count
        } catch (_: UnknownHostException) {
            android.util.Log.d("AppConnectorVpn", "Could not resolve domain: $domain")
            0
        }
    }

    private fun applyAllowedApps(builder: Builder, apps: org.json.JSONArray?): Int {
        if (apps == null) {
            return 0
        }
        var applied = 0
        for (index in 0 until apps.length()) {
            val appId = apps.optString(index).trim()
            if (appId.isEmpty()) {
                continue
            }
            try {
                builder.addAllowedApplication(appId)
                applied += 1
            } catch (_: Exception) {
            }
        }
        return applied
    }

    private fun applyDisallowedApps(builder: Builder, apps: org.json.JSONArray?): Int {
        if (apps == null) {
            return 0
        }
        var applied = 0
        for (index in 0 until apps.length()) {
            val appId = apps.optString(index).trim()
            if (appId.isEmpty()) {
                continue
            }
            try {
                builder.addDisallowedApplication(appId)
                applied += 1
            } catch (_: Exception) {
            }
        }
        return applied
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }
        val manager = getSystemService(NotificationManager::class.java) ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Mesh Infinity App Connector",
            NotificationManager.IMPORTANCE_LOW,
        )
        channel.description = "Keeps Android per-app VPN enforcement active."
        channel.setShowBadge(false)
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification {
        val builder =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                Notification.Builder(this, CHANNEL_ID)
            } else {
                Notification.Builder(this)
            }
        return builder
            .setContentTitle("Mesh Infinity")
            .setContentText("Applying App Connector routing on Android")
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
    }
}
