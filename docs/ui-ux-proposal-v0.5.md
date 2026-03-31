# Mesh Infinity UI/UX Proposal — v0.5

**Date:** 2026-03-31
**Based on:** Research into Signal, Discord, Element (Matrix), Telegram, Briar, Meshtastic, Tailscale, and Authentik
**Scope:** Adjustments to §22 of SPEC.md to align with industry-proven patterns

---

## Executive Summary

The current UI spec (§22) defines a solid foundation with responsive breakpoints, Material 3, and feature-scoped screens. This proposal identifies **27 concrete adjustments** to align Mesh Infinity's UX with patterns proven at scale by Signal (messaging), Discord (communities), Tailscale (mesh networking), and Authentik (identity/permissions). The goal is not to copy these apps but to adopt the UX idioms users already understand, while preserving Mesh Infinity's privacy-first identity.

---

## 1. Navigation & Shell

### 1.1 Adopt Discord's Guild Sidebar for Gardens

**Current:** Single bottom-nav tab labeled "Garden" shows a flat list of communities.

**Proposal:** Add a narrow (56px) vertical icon strip on the far left (desktop/tablet) showing Garden avatars, identical to Discord's server list. This persists across all sections so users can jump to a Garden without navigating back to the Garden tab.

**Why:** Users with 5+ communities need instant switching. Discord proved this pattern at 200M+ MAU. The icon strip also serves as a visual anchor — "I'm in this community" is always visible.

**Mobile:** The icon strip becomes a horizontally scrollable row at the top of the Garden screen (like Telegram's folder tabs).

### 1.2 Merge Chat + Garden into a Single "Messages" Section

**Current:** Separate "Chat" and "Garden" tabs in the bottom nav (6 sections total).

**Proposal:** Merge into a single "Messages" section with sub-filters:
- **All** — unified inbox (DMs + Garden messages, sorted by recency)
- **Direct** — 1:1 conversations only
- **Gardens** — community messages grouped by Garden

**Why:** Signal's unified conversation list is simpler to navigate. Six bottom-nav items are too many — five is the established maximum (Google Material guidelines). Users think in terms of "messages" not "chat vs garden."

**Result:** 5 sections: **Messages**, **Files**, **Contacts**, **Network**, **Settings**

### 1.3 Signal-Style Conversation List Items

**Current:** Basic ListTile with name, last message, timestamp.

**Proposal:** Each conversation item shows:
- Circular avatar (left, 48px) with online indicator dot
- **Name** (bold) + **timestamp** (right-aligned, relative: "now", "5m", "3:42 PM", "Mon", "Mar 15")
- **Last message preview** (secondary text, single line, gray). In groups: `SenderName: message`. For media: "Photo", "Voice Message", "File: report.pdf"
- **Delivery status** (outgoing only): hollow circle → single check → double check → filled double check
- **Unread badge** (count in colored circle, right side)
- **Mute icon** (bell-slash, next to name when muted)
- **Typing indicator** (animated dots replace preview when someone is typing)
- **Pinned indicator** (pin icon, pinned items float to top, max 4)

**Why:** Signal's conversation list is the most information-dense-yet-readable pattern in the industry. Every element serves a purpose.

### 1.4 Desktop Three-Pane for Messages

**Current:** Three-pane defined in spec but partially implemented.

**Proposal (desktop ≥1200px):**
```
┌──────┬────────────┬──────────────────────┐
│Icons │ Conv List  │    Thread View       │
│(56px)│  (300px)   │    (remaining)       │
│      │            │                      │
│ DM   │ ▸ Alice    │  [message bubbles]   │
│ 🌿A  │   Bob      │                      │
│ 🌿B  │ ▸ Garden X │  ┌──────────────┐   │
│      │   ...      │  │ input area   │   │
│ ⚙️   │            │  └──────────────┘   │
└──────┴────────────┴──────────────────────┘
```

- Left strip: Garden icons + DM icon + Settings gear (bottom)
- Middle: Conversation list (filterable)
- Right: Active thread

**Tablet (760-1199px):** Omit the icon strip; use NavigationRail + list + thread.

**Mobile (<760px):** Stack: list → thread (push navigation).

---

## 2. Messaging UX

### 2.1 Message Bubbles (Signal-Inspired)

**Current:** Basic bubbles with alignment.

**Proposal:**
- Outgoing: right-aligned, brand blue background (#2C6EE2), white text
- Incoming: left-aligned, surface variant background (adaptive to theme)
- **Consecutive clustering:** Messages from the same sender within 2 minutes share a single avatar and reduced spacing. Only the last message in a cluster shows the tail.
- **Date dividers:** Centered pill labels ("Today", "Yesterday", "March 15")
- **Hidden timestamps:** Individual timestamps hidden by default. Tap (mobile) or hover (desktop) to reveal. This reduces visual noise dramatically.
- **Group sender colors:** Assign a deterministic color per member (hash peer_id to one of 8 palette colors). Show colored sender name above first bubble in a cluster.

### 2.2 Reactions (Signal Model)

**Current:** Not implemented.

**Proposal:** Long-press a bubble → floating emoji bar (6 defaults + "+" for full picker). Reactions appear as small emoji badges below the bubble with count. Tapping the badge shows who reacted.

**Why:** Reactions reduce message volume ("👍" replaces "Sounds good!") and increase engagement. Signal's implementation is the gold standard for privacy (reactions are encrypted like any other message).

### 2.3 Reply/Quote (Signal Model)

**Current:** Partially implemented.

**Proposal:** Swipe right on a message to quote. Quoted message appears as a compact card above the compose area with colored left bar (sender's color) + truncated text + optional media thumbnail. Tapping the quote in the thread scrolls to and highlights the original.

### 2.4 Voice Messages (Signal Model)

**Proposal:**
- Empty input → mic icon replaces send button
- Hold to record, slide left to cancel, slide up to lock (hands-free)
- Inline playback with waveform visualization + duration
- Play speed: 1x/1.5x/2x toggle

### 2.5 Message Security Mode Picker

**Current:** Defined in spec §22.5.2 but not implemented.

**Proposal:** Keep the spec's 5-mode picker but simplify the UX:
- Default to "Standard" (no user action needed)
- Show current mode as a small shield icon in the chat header
- Tap the shield → bottom sheet with 5 options + brief description each
- Changing to a lower security mode requires a confirmation dialog
- Changing to a higher mode is instant

### 2.6 Disappearing Messages

**Proposal:** Timer icon in chat header (like Signal). Options: Off, 30s, 5m, 1h, 8h, 1d, 1w, 4w. System message when changed. Timer countdown icon on each ephemeral message.

---

## 3. Gardens (Communities) — Discord-Inspired

### 3.1 Garden Structure

**Proposal:** Each Garden contains:
- **Channels** organized in collapsible **Categories** (like Discord)
- Channel types: Text (#), Voice (🔊), Announcement (📢)
- Channel-level access control (which roles can see/post)
- **Member list** visible in a right panel (desktop) or via a members icon (mobile)

### 3.2 Garden Sidebar (Desktop)

```
┌─────────────────────┐
│ 🌿 Garden Name ▾   │ ← tap for settings
├─────────────────────┤
│ ▾ GENERAL           │ ← category (collapsible)
│   # general         │
│   # announcements   │
│   🔊 voice-lobby   │
├─────────────────────┤
│ ▾ PROJECTS          │
│   # project-alpha   │
│   # project-beta    │
└─────────────────────┘
```

**Mobile:** Top bar shows Garden name + channel name. Hamburger (☰) or swipe-right reveals the channel list as a drawer.

### 3.3 Garden Discovery

**Proposal:** Public Gardens are discoverable via a "Browse Gardens" screen:
- Search by name/description
- Category tags (Technology, Privacy, Local, Social, etc.)
- Preview: name, description, member count, channel count
- "Join" button → enter the Garden
- Private Gardens require an invite link (shareable, expirable)

### 3.4 Garden Roles (Discord + Authentik Hybrid)

**Proposal:** Roles panel in Garden Settings:
- Visual role list with color badges (like Discord)
- Permission matrix per role: Read, Write, Manage Members, Manage Channels, Admin
- Channel-level overrides: per-channel permission tweaks (like Discord's channel permissions)
- **From Authentik:** Show a clear permission summary card for each role, listing what it can/cannot do in plain language

### 3.5 Garden Notifications (Discord Model)

**Per-channel settings:**
- All Messages
- @mentions only (default)
- Nothing
- Mute duration: 15m, 1h, 8h, 24h, Until I turn it back on

**@everyone / @here mentions:** Require Moderator+ role to use. Opt-out toggle per Garden.

---

## 4. Network & Transport UX — Tailscale-Inspired

### 4.1 Connection Status (Tailscale Model)

**Current:** Network screen with transport toggles.

**Proposal:** Persistent, minimal status indicator in the app bar:
- 🟢 Green dot: connected (direct or relay)
- 🟡 Yellow dot: connecting / degraded
- 🔴 Red dot: disconnected
- Tap → expands to full network status sheet

**Why:** Tailscale's genius is making VPN status a single dot. Users don't need to know about WireGuard, circuits, or NAT traversal — they need to know "am I connected?"

### 4.2 Peer Status (Tailscale Machine List)

**Proposal:** Peer list shows:
- Peer name + avatar
- Status: Online (green), Idle (yellow), Offline (gray)
- Connection type: "Direct" or "Relayed" (small label)
- Last seen timestamp (for offline peers)
- Trust level badge (colored pill)

**Why:** Tailscale's machine list proves you can show networking info (IP, status, connection type) without being overwhelming.

### 4.3 Network Dashboard (New Screen)

**Proposal:** Replace the current transport-toggles-only Network screen with a dashboard:

**Overview tab:**
- Connection status card (connected peers count, active transports, data transferred)
- Transport health grid: small cards per transport (Clearnet ✓, Tor ✓, BLE ✗, etc.) with enable/disable toggle
- Active tunnels list (peer name + transport + latency)

**Topology tab:**
- Simple visualization: your node in the center, connected peers as nodes around it
- Lines between nodes colored by transport type
- Tap a peer → shows route (direct or via relay hops)

**Why:** Mesh topology is Mesh Infinity's unique differentiator. Briar and Meshtastic both show connection topology; it's expected in this space.

### 4.4 Transport Detail Screens

Each transport gets a detail screen accessible from the health grid:
- **Tor:** Bootstrap progress, onion address, circuit count
- **Clearnet:** Listen port, connected peers, NAT type
- **Bluetooth:** Nearby devices, connected devices, range estimate
- **SDR/RF:** Frequency, channel, signal strength, hop table

### 4.5 Simplified Transport Language

**From Tailscale:** Avoid jargon in the main UI. Instead of "WireGuard session established with peer X via clearnet transport," show "Connected to Alice (direct)." The technical details go in the detail screens, not the main flow.

---

## 5. Identity & Permissions — Authentik-Inspired

### 5.1 Trust Level Visualization

**Current:** 4-level trust (spec requires 9).

**Proposal:** Update to 9-level trust with Authentik's three-layer permission model:

**Layer 1 — Trust levels as groups:** Each level (0–8) is a "group" that inherits all permissions from the levels below. Level 3 (Acquaintance) automatically gets everything Level 2 (Vouched) has, plus its own additions.

**Layer 2 — Permission cards per level:** Each trust level shows a clear card listing what it permits:
- "Level 0: Unknown — Can discover you on LAN, nothing else"
- "Level 3: Acquaintance — Can send messages, share files up to 10MB, join your public Gardens"
- "Level 7: Highly Trusted — Full access, can relay traffic, admin in your Gardens"

**Layer 3 — Per-object permissions tab:** Every peer, transport, and plugin in the UI has a "Permissions" tab showing exactly which trust levels can access it. This is Authentik's most powerful pattern — you never have to hunt for who has access to what.

### 5.2 Identity Dashboard

**Proposal:** Combine the scattered identity screens into a single dashboard (Authentik's tabbed user detail pattern):

- **Overview** tab: peer ID, display name, avatar, public key fingerprint, QR code
- **Masks** tab: list of active masks with per-mask stats (messages sent, contacts using this mask)
- **Sessions** tab: active connections/devices with revoke capability (like Authentik's session management)
- **Security** tab: active threats, key expiry countdown, backup status, safety number verification status
- **Activity** tab: recent events for this identity (logins, key changes, trust level changes)

### 5.3 Plugin Permissions (Authentik Policy Binding Model)

**Proposal:** Use Authentik's three-part binding architecture:

**Plugin list** — card grid (like Authentik's Application cards):
- Icon, name, author, version, status badge (Active ● / Suspended ○)
- Tap → detail screen

**Plugin detail** — tabbed view:
- **Overview**: description, version, author
- **Permissions**: checklist of requested vs granted permissions (✅ Read Messages, ✅ Network Access, ❌ Crypto Access). Toggle individual permissions on/off.
- **Hooks**: which events this plugin listens to, with enable/disable per hook
- **Activity**: last 10 invocations with timing (from `HookInvocation` data)
- **Permissions tab on other objects**: when viewing a transport or peer, a "Plugins" sub-tab shows which plugins have access to it

**Policy engine for plugins** — adopt Authentik's ALL/ANY model:
- "Plugin X requires: Trust Level ≥ 3 **AND** Network Access permission" (ALL mode)
- "Plugin Y requires: Trust Level ≥ 5 **OR** Manual admin approval" (ANY mode)

### 5.4 Audit Log (Authentik Event Model)

**Proposal:** Full audit/activity log accessible from Settings → Security:

**Event list:**
- Chronological, with volume histogram at the top (Authentik's key pattern for spotting spikes without reading individual entries)
- Event types: key change, trust level change, pairing attempt, plugin activity, connection failure, transport change
- Severity: info (gray), warning (amber), alert (red)
- Filter with advanced query: `action=trust_change peer~alice`

**Event detail:**
- Full context: who, what, when, which transport, which peer
- Automatic credential stripping (no key material in logs, per §15.1)

**Notification rules** (Authentik's event-matcher pattern):
- "Notify me when a peer's trust level changes" → local notification
- "Alert on 5+ failed connections from unknown peer in 1 hour" → security alert
- Configurable per-event-type: local bell, push notification, or silent log-only

### 5.5 Trust Workflows (Authentik Flow Model)

**New proposal:** Map Authentik's "Flow as sequence of Stages" to peer trust promotion:

Each trust level transition is a "flow" with configurable stages:
- **Level 0 → 1 (Discovery → Seen)**: Automatic after first successful handshake
- **Level 1 → 2 (Seen → Vouched)**: Requires: mutual QR scan OR vouching by a Level 5+ peer
- **Level 2 → 3 (Vouched → Acquaintance)**: Requires: 24h waiting period + one successful message exchange
- Higher levels: configurable by the user (like Authentik's flow customization)

Each stage can have policies bound: "skip the 24h wait if the peer was vouched by 2+ inner-circle contacts" (Authentik's per-stage policy binding).

### 5.6 Reputation Scoring (Authentik Reputation Policy)

**New proposal:** Automatic trust scoring based on peer behavior:
- Track connection success/failure ratio per peer
- Track message delivery reliability
- Track uptime/availability history
- Display as a small trend indicator (↑ improving, → stable, ↓ declining) next to the trust badge
- Reputation drops below threshold → automatic trust demotion warning
- Configurable thresholds (Settings → Security → Reputation)

---

## 6. Files

### 6.1 Two-Tab Structure

**Current:** Single transfers tab.

**Proposal:** Two tabs in the Files section:
- **Transfers** — active and completed file transfers (current implementation)
- **Storage** — distributed file storage with publish/unpublish, stickiness scores, security badges

### 6.2 Transfer Progress (Signal-Inspired)

Show transfers inline in conversations (not just in the Files tab):
- Outgoing file: message bubble with filename, size, progress bar
- Incoming file: bubble with filename, size, "Accept" / "Decline" buttons
- Completed: bubble becomes a tappable card with file icon + name

---

## 7. Onboarding

### 7.1 Simplified Flow

**Current:** Identity check → QR display → Get Started.

**Proposal (Signal + Tailscale hybrid):**

1. **Welcome** — "Mesh Infinity" branding, one-line description, "Get Started" button
2. **Create Identity** — Generate keypair (show progress), optional passphrase
3. **Set Profile** — Display name + avatar (optional, skippable)
4. **Connect** — "How do you want to connect?" → toggles for Clearnet (default on), Tor, Bluetooth. Brief plain-language explanation per option. Advanced users can customize later.
5. **Add First Contact** — QR code scanner + your QR code side by side. "Skip for now" option.
6. **Done** — "You're ready!" → enter the app

**Why:** Tailscale's onboarding is 3 screens. Signal's is 4. We should not exceed 6 for the core flow. Every extra screen loses 20% of users.

---

## 8. Security UX

### 8.1 Security Status Bar (§22.4.1)

**Current:** Defined in spec but not implemented.

**Proposal:** Implement as a persistent, dismissible banner:
- LoSec mode active: amber bar, "Reduced security — fast mode"
- Key change detected: amber bar, "Alice changed security keys — Verify"
- Compromised peer: red bar, "[Peer] may be compromised"
- Direct connection (no encryption): red bar, "Unencrypted connection"

Tap → relevant detail screen. Swipe to dismiss (re-appears on next relevant event).

### 8.2 Safety Number Screen (Signal Model)

When tapping a peer's trust badge:
- Show the safety number as both a numeric grid (Signal-style) AND a QR code
- "Scan Their Code" and "Share My Code" buttons
- Verification status: "Verified ✓" or "Not Yet Verified"
- "What is this?" expandable explainer

### 8.3 Encryption Indicator

**Proposal:** Every conversation shows a small lock icon in the header:
- 🔒 Encrypted (default, green)
- 🔒 Post-quantum (purple, if PQXDH active)
- ⚠️ Degraded (amber, if LoSec or missing PQ)
- 🔓 Unencrypted (red, direct mode only)

---

## 9. Global Patterns

### 9.1 Pull-to-Refresh on All Lists

Already in the spec — keep it.

### 9.2 Swipe Actions on List Items

- **Swipe right:** Pin conversation / Accept transfer
- **Swipe left:** Archive / Delete / Mute (with options)
- Show the action icon under the swiped area

### 9.3 Empty States

Every list screen gets a dedicated empty state:
- Large icon (64px, outline style)
- Title ("No messages yet")
- Subtitle ("Start a conversation by tapping the compose button")
- Optional CTA button

### 9.4 Loading States

Skeleton screens (shimmer) for all list views while loading. Never show a blank screen.

### 9.5 Dark Mode

Full dark mode support. Follow system preference by default, with manual override in Settings.

---

## 10. Summary of Changes to §22

| §22 Section | Change |
|---|---|
| §22.0 Navigation | Reduce to 5 sections (merge Chat+Garden) |
| §22.1 Design System | Add conversation list item spec, trust level 9-color palette |
| §22.4 Global Widgets | Add security status bar, trust badge (9-level), encryption indicator |
| §22.5 Chat | Add message clustering, hidden timestamps, reactions, voice messages, reply/quote |
| §22.6 Garden | Rewrite as Discord-style channels + categories + member panel |
| §22.7 Files | Add storage tab, inline transfer progress in conversations |
| §22.8 Contacts | Update trust to 9 levels, add Tailscale-style status display |
| §22.9 Network | Replace toggles-only with dashboard (overview + topology) |
| §22.10 Settings | Add identity dashboard, plugin permissions, audit log |
| §22.11 Onboarding | Simplify to 6-screen flow |
| NEW §22.12 | Security UX patterns (status bar, safety numbers, encryption indicators) |

---

---

## 11. Mesh-Specific Patterns (from Briar, Meshtastic, Tailscale, Retroshare)

### 11.1 Message Delivery Status (Briar + Meshtastic)

**Critical for mesh:** Messages may be queued, in-transit across hops, or delivered. Users MUST see distinct states:
- ○ **Queued** (hollow circle) — stored locally, peer offline
- ◐ **In transit** (half-filled) — forwarded by relay/intermediate node, awaiting final delivery
- ● **Delivered** (filled circle) — peer confirmed receipt
- ✕ **Failed** (red X) — max retransmissions reached

**Why:** Briar's biggest UX flaw is showing "sent" for queued messages. Meshtastic's green/yellow/red outline system is more honest. Mesh users need to understand that "sent" ≠ "delivered."

### 11.2 Transport Indicator (Meshtastic Traffic-Light)

Per-peer connection quality using Meshtastic's color system:
- 🟢 **Direct** — peer-to-peer, low latency
- 🟡 **Relayed** — via intermediate node(s), higher latency
- 🔴 **Unreachable** — no active route
- Plus a small label: "Direct", "1 hop", "2 hops", "Tor"

### 11.3 Silent Connection Upgrade (Tailscale)

**Pattern:** All connections start relayed, then silently upgrade to direct when possible. Show users the RESULT, not the negotiation. Never show "connecting... trying NAT traversal... falling back to relay..." — just show "Connected (relayed)" → "Connected (direct)" when the upgrade completes.

### 11.4 Name-Based Addressing (Tailscale MagicDNS)

Peers should be addressable by display name, not peer ID hex strings. The UI should never show `a4f2c8...` to users — always resolve to a display name. Peer IDs are for the protocol layer, names are for the human layer.

### 11.5 Network Health Status Bar (Retroshare)

Persistent mini-bar at the bottom of the screen (desktop) or in the Network section header (mobile):
- Connected peers count
- Active transports (icons: 🌐 Clearnet, 🧅 Tor, 📡 BLE)
- Bandwidth: ↑ 2.4 KB/s ↓ 8.1 KB/s
- NAT status: Full cone / Restricted / Symmetric

### 11.6 QR Mutual Scan for Pairing (Briar Gold Standard)

The pairing screen should show BOTH the user's QR code AND a camera viewfinder simultaneously (split screen). Both peers scan each other. This is the highest-trust pairing method and should be the primary flow.

### 11.7 Progressive Disclosure (Meshtastic + Tailscale)

- **Tap** → basic info (peer name, status, trust level)
- **Long-press** → power actions (copy peer ID, ping, block, change trust)
- **Navigate to detail** → full diagnostics (route, transport, latency, key info)

### 11.8 Offline-First Forum Sync (Retroshare + Briar)

Garden channels should support offline read/write. Messages composed offline are queued and auto-sync when connectivity returns. The UI shows a subtle "offline" badge on queued messages but does NOT block the user from composing.

---

---

## 12. Network Management Dashboard — NetBox / Grafana / LibreNMS / Unifi Inspired

### 12.1 "Is Everything OK?" View (LibreNMS Availability Grid)

The Network section's first screen should answer one question: **is everything working?**

**Availability tile grid:** One colored tile per active transport + one per connected peer.
- 🟩 Green = healthy (connected, low latency)
- 🟨 Yellow = degraded (high latency, packet loss, relay-only)
- 🟥 Red = down (disconnected, unreachable)
- ⬜ Gray = disabled (transport off, peer offline)

For 10-100 nodes this is scannable at a glance. Above 100, group by trust level or Garden membership and show group-level aggregates.

**Why:** LibreNMS and Zabbix both use this as their primary monitoring view. When everything is green, the operator sees a wall of green and moves on. A single red tile draws the eye instantly.

### 12.2 KPI Stat Row (Grafana Stat Panels)

Top of the Network dashboard — a row of 4-5 stat panels:
- **Peers Online**: big number + sparkline trend (e.g., "14" with a 24h micro-chart)
- **Active Transports**: count + icons (🌐 🧅 📡)
- **Messages/sec**: throughput indicator
- **Bandwidth**: ↑ 2.4 KB/s ↓ 8.1 KB/s
- **Alerts**: count with severity coloring (0 = green, 1+ = amber/red)

**Why:** Grafana's stat panel pattern is the industry standard for operational dashboards. One row tells you the health of the system in 2 seconds.

### 12.3 Mesh Topology Visualization (Grafana Node Graph + LibreNMS Maps)

**Node graph panel** — interactive mesh topology view:
- **Your node** in the center, highlighted
- **Peers** as circles radiating outward, sized by trust level
- **Arc segments** on each node showing connection type proportions (60% clearnet = blue arc, 40% Tor = purple arc)
- **Edges** (connections) with:
  - Color gradient for quality: green → yellow → red (based on latency/loss)
  - Thickness for bandwidth
  - Dashed lines for relay, solid for direct
  - Dotted for Tor circuits
- **Layout modes:** Force-directed (default), Grid (sorted by trust level or latency), Manual (user-placed)

**Interaction:**
- Tap a node → peer detail popover
- Tap an edge → connection detail (transport, latency, hops)
- Pinch to zoom, pan to scroll
- Long-press a node → context menu (ping, trace route, block, change trust)

**Why:** Grafana's node graph panel with arc segments is the most expressive graph visualization available. LibreNMS's utilization color gradient is universally understood.

### 12.4 Connection Route Tracing (NetBox Cable Trace)

**Tap an edge or select "Trace Route" from a peer's context menu:**
- Show the full path: Your Node → Relay A → Relay B → Destination Peer
- Each hop as a card: node name, transport type, latency for that hop
- Highlight the path on the topology graph
- Total end-to-end latency at the top

**Why:** NetBox's cable trace with path highlighting is the gold standard for "how does data get from A to B?" This is critical for mesh debugging.

### 12.5 Transport Health Cards (Cockpit + pfSense)

Replace the current transport toggle list with detailed cards per transport:

```
┌─────────────────────────┐
│ 🌐 Clearnet       [ON] │
│ Port 7234 · 8 peers     │
│ ↑ 2.1 KB/s  ↓ 5.3 KB/s │
│ ▃▅▇▅▃▂▅▇▅▃ (24h graph) │
└─────────────────────────┘
```

Each card shows: transport icon + name, enable/disable toggle, connected peer count, bandwidth sparkline, and tap → full detail screen.

**Why:** Cockpit's per-interface cards with inline graphs are the cleanest way to show multiple transport statuses simultaneously.

### 12.6 Alert Management (Prometheus AlertManager)

**Three-state alerts:** Pending → Firing → Resolved (with color coding)

**Alert grouping:** Similar alerts bundled (e.g., "3 peers unreachable via Tor" instead of 3 separate alerts)

**Silencing:** When doing maintenance or testing, create a silence:
- Match: "transport = tor" or "peer = alice"
- Duration: 1h, 4h, 24h, custom
- Reason: "Tor exit node maintenance"

**Inhibition:** Suppress downstream alerts when root cause is firing (e.g., suppress all "peer unreachable" alerts when "clearnet transport down" is active)

**Why:** AlertManager's grouping + silencing + inhibition triad is the only proven approach to preventing alert fatigue in systems with many interconnected components.

### 12.7 Trust Zone Matrix (pfSense/OPNsense Zone Firewall)

A grid showing what each trust level can do with each transport/feature:

```
              │ Clearnet │  Tor  │  BLE  │ Files │ Gardens │
─────────────┼──────────┼───────┼───────┼───────┼─────────┤
 Unknown (0) │    ─     │   ─   │  ─    │  ─    │   ─     │
 Seen (1)    │    R     │   ─   │  R    │  ─    │   ─     │
 Vouched (2) │    RW    │   R   │  RW   │  R    │   R     │
 Trusted (5) │    RW    │   RW  │  RW   │  RW   │   RW    │
 Inner (8)   │    RW+   │   RW+ │  RW+  │  RW+  │   RW+   │
```

(R = read, W = write, + = admin, ─ = blocked)

**Why:** pfSense's zone matrix is the fastest way to audit "who can do what" across the entire system. One screen, complete visibility.

### 12.8 Peer Adoption Flow (Unifi Device Adoption)

When a new peer is discovered on the network:
1. **Pending** state — appears in a "New Peers" section with a pulsing indicator
2. **Preview** — tap to see peer info (public key fingerprint, transport, trust level 0)
3. **Adopt** — one-tap to promote to Seen (trust level 1), or scan QR for higher trust
4. **Configure** — optionally set display name, assign to a Garden, set initial trust level

**Why:** Unifi's adopt-then-configure flow is the cleanest onboarding pattern for new network members.

### 12.9 State Timeline (Grafana)

Per-peer connectivity history as horizontal swim lanes:
```
Alice  ████████████░░░░████████████████
Bob    ████████████████████████░░████████
Tor    ████████████████████████████████
BLE    ░░░░░░░░░░░░████░░░░░░░░░░░░░░░
       |--- 24h ago ---|--- 12h ---|-- now
```

Green = connected, gray = disconnected, amber = degraded.

**Why:** Grafana's state timeline compresses 24h of node history into a single line. Patterns (daily disconnections, intermittent failures) become immediately visible.

---

---

## 13. Mesh Routing & Anonymity Network Patterns — cjdns / Yggdrasil / I2P / Tor / ZeroTier

### 13.1 Circuit/Tunnel Visualization (Tor Nyx + I2P Console)

**For Tor connections:** Show the circuit as a chain of relay nodes:
```
You → Guard (DE) → Middle (CH) → Exit (NL) → destination.onion
      45ms          82ms          120ms
```

Each relay shows: country flag, latency for that hop, and a "New Circuit" button to request a fresh path. This is how Tor Browser displays circuits.

**For I2P tunnels:** Show inbound and outbound tunnel health:
- Tunnel count (target vs actual)
- Participation rate (how many transit tunnels you're serving)
- Bandwidth allocation sliders (share %, speed limit)

**For mesh multi-hop:** Show the path through relay peers:
```
You → Alice (direct, 12ms) → Bob (relay, 45ms) → Charlie (direct, 8ms)
```

### 13.2 Peer Health Metrics (I2P Peer Profiles)

I2P profiles each peer on three dimensions — adopt this for mesh:
- **Speed**: bandwidth capacity tier (1-4 stars)
- **Capacity**: how many tunnels/connections this peer can handle
- **Integration**: how well-connected this peer is in the network (analogous to routing table completeness)

Display as a compact 3-bar mini-chart next to each peer in the peer list.

### 13.3 Network Database Explorer (I2P NetDB)

For power users, expose a searchable "Network Map" explorer:
- List of known peers with: peer ID (truncated), trust level, last seen, transport types, speed tier
- Filter by: trust level, online status, transport capability
- Sort by: last seen, speed, hop count

This is I2P's NetDB browser adapted for mesh context.

### 13.4 ZeroTier Member Authorization Model

When a new peer joins the mesh, use ZeroTier Central's pattern:
- New peer appears as **unauthorized** in the member list
- Admin sees a toggle to **authorize** (grant network access)
- Authorized peers can be assigned to **flow groups** (like ZeroTier's flow rules)
- De-authorization immediately drops all connections

This maps directly to trust level promotion: Level 0 (discovered) → admin authorizes → Level 1+ (seen/vouched).

---

## 14. File Sharing & Storage — Syncthing / IPFS / qBittorrent / OnionShare Inspired

### 14.1 Sync Status Three-Metric Model (Syncthing)

For distributed files, show three numbers per shared folder:
- **Global**: total files/bytes across all peers (the "truth")
- **Local**: what this device has (your copy)
- **Out of Sync**: the delta (what needs to be fetched/sent)

```
┌─────────────────────────────────────┐
│ 📁 Project Files                    │
│ Global: 142 files, 2.3 GB          │
│ Local:  138 files, 2.1 GB          │
│ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░ 97% synced    │
│ Syncing... 4 files remaining        │
└─────────────────────────────────────┘
```

**Why:** Syncthing's Global/Local/Delta model is the clearest way to communicate distributed file state. Users immediately understand what they have vs what exists.

### 14.2 Piece Map (qBittorrent)

For large file transfers, show a visual piece map:
- Horizontal bar divided into segments
- Green = downloaded, gray = missing, blue = in progress
- Hover/tap a segment to see which peer is providing it

This is particularly relevant for mesh file sharing where chunks may come from different peers.

### 14.3 Peer Contribution per Transfer (qBittorrent Peer List)

Per active transfer, show which peers are contributing:
```
Peers for "report.pdf":
  Alice  ████████░░  80%  ↓ 45 KB/s  (direct)
  Bob    ██░░░░░░░░  20%  ↓ 12 KB/s  (relay)
```

### 14.4 Share Management (Nextcloud + OnionShare)

For publishing files to the mesh:
- **Share link generation**: create a link with permissions (view/download/upload)
- **Expiry**: set an auto-expire time
- **Password**: optional passphrase protection
- **Access log**: who accessed the share, when

OnionShare's pattern of **ephemeral one-time addresses** is perfect for sensitive shares — the address disappears after the first download.

### 14.5 Pending Device/Share Notifications (Syncthing)

When a peer offers to share a file or folder:
- A notification card appears in the Files section
- Shows: peer name, file/folder name, size
- Actions: **Accept**, **Ignore**, **Block**
- Ignored offers don't reappear; blocked peers can't send new offers

### 14.6 Bandwidth Throttling (Syncthing + qBittorrent)

Settings → Network → Bandwidth:
- Incoming rate limit (KB/s slider)
- Outgoing rate limit (KB/s slider)
- "Limit on metered connections" toggle (auto-detect Wi-Fi vs cellular)
- Per-transport limits (e.g., limit Tor to 50 KB/s, no limit on clearnet)

---

## Appendix: Research Sources

- **Signal:** Conversation list, message bubbles, reactions, voice messages, read receipts, disappearing messages, safety numbers
- **Discord:** Server/channel hierarchy, category organization, role management, notification per-channel, member list, server discovery
- **Tailscale:** Connection status dot, machine list, "just works" philosophy, simplified technical language
- **Authentik:** Permission cards, policy visualization, session management, audit log
- **Element (Matrix):** Spaces, room directory, encryption verification
- **Briar:** Transport status indicators, QR pairing, offline messaging UX
- **Meshtastic:** Mesh topology visualization, radio configuration UX
- **NetBox:** Path tracing, tag system, role-based coloring, IPAM sunburst
- **LibreNMS:** Availability tile grid, link utilization color gradients, custom network maps
- **Grafana:** Stat panels, node graph with arc segments, state timeline, variable dropdowns
- **Prometheus/AlertManager:** Three-state alerts, grouping, silencing, inhibition
- **Cockpit:** Stacked area graphs, per-interface cards, zone-based firewall
- **pfSense/OPNsense:** Drag-to-reorder rules, zone matrix, live rule matching
- **Unifi:** Auto-layout topology, device adoption flow, signal strength bars
- **cjdns/Yggdrasil:** DHT routing table display, spanning tree visualization
- **I2P:** Tunnel management, peer profiles (speed/capacity/integration), NetDB explorer
- **Tor/Nyx:** Circuit visualization, bandwidth graphs, relay detail
- **ZeroTier:** Member authorization toggle, flow rules editor
- **Syncthing:** Global/Local/Delta sync model, pending device notifications, folder types
- **IPFS:** Content-addressed browsing, pin management
- **qBittorrent:** Piece map, per-peer contribution, bandwidth scheduling
- **OnionShare:** Ephemeral one-time shares, receive mode
- **Nextcloud:** Share management with expiry/password/access log
