//
//  TrustNetworkView.swift
//  NetInfinity
//

import SwiftUI
#if os(macOS)
import AppKit
#elseif canImport(UIKit)
import UIKit
#endif

struct TrustNetworkView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var dependencyContainer: AppDependencyContainer

    @State private var peers: [PeerIdentity] = []
    @State private var pairingCodeInput = ""
    @State private var selectedMethod: VerificationMethod = .inPerson
    @State private var isPairing = false
    @State private var showError = false
    @State private var errorMessage = ""

    private var pairingCode: String {
        dependencyContainer.trustService.pairingCode(for: appState.currentIdentity)
    }

    var body: some View {
        List {
            Section("Your Pairing Code") {
                VStack(alignment: .leading, spacing: 8) {
                    Text(pairingCode)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)

                    Button("Copy Pairing Code") {
                        copyPairingCode()
                    }
                    .buttonStyle(.bordered)
                }
                .padding(.vertical, 4)
            }

            Section("Pair New Peer") {
                TextField("Enter pairing code", text: $pairingCodeInput)
                    .platformAutocapitalization(.none)
                    .platformAutocorrectionDisabled(true)

                Picker("Verification Method", selection: $selectedMethod) {
                    ForEach(VerificationMethod.allCases) { method in
                        Text(method.title).tag(method)
                    }
                }

                Text("Default trust: \(selectedMethod.defaultTrust.title)")
                    .font(.footnote)
                    .foregroundColor(.secondary)

                Button(isPairing ? "Pairing..." : "Pair Peer") {
                    pairPeer()
                }
                .disabled(isPairing || pairingCodeInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }

            Section("Trusted Peers") {
                if peers.isEmpty {
                    Text("No trusted peers yet. Pair with a peer to build your trust network.")
                        .foregroundColor(.secondary)
                } else {
                    ForEach(peers) { peer in
                        PeerRow(
                            peer: peer,
                            onTrustChange: { level in
                                updateTrust(peerId: peer.id, level: level)
                            },
                            onEndorse: { level in
                                endorsePeer(peerId: peer.id, level: level)
                            },
                            onRemove: {
                                removePeer(peerId: peer.id)
                            }
                        )
                    }
                }
            }
        }
        .navigationTitle("Trust & Pairing")
        .platformNavigationBarTitleDisplayMode(.inline)
        .task {
            await loadPeers()
        }
        .refreshable {
            await loadPeers()
        }
        .alert("Pairing Error", isPresented: $showError) {
            Button("OK", role: .cancel) { }
        } message: {
            Text(errorMessage)
        }
    }

    // MARK: - Actions

    private func loadPeers() async {
        do {
            let peers = try await dependencyContainer.trustService.listPeers()
            await MainActor.run {
                self.peers = peers.sorted { lhs, rhs in
                    if lhs.trustLevel != rhs.trustLevel {
                        return lhs.trustLevel > rhs.trustLevel
                    }
                    return lhs.lastSeen > rhs.lastSeen
                }
            }
        } catch {
            await MainActor.run {
                errorMessage = error.localizedDescription
                showError = true
            }
        }
    }

    private func pairPeer() {
        isPairing = true
        let code = pairingCodeInput
        Task {
            do {
                _ = try await dependencyContainer.trustService.addPeer(
                    pairingCode: code,
                    verificationMethod: selectedMethod
                )
                await MainActor.run {
                    pairingCodeInput = ""
                }
                await loadPeers()
            } catch {
                await MainActor.run {
                    errorMessage = error.localizedDescription
                    showError = true
                }
            }
            await MainActor.run {
                isPairing = false
            }
        }
    }

    private func updateTrust(peerId: String, level: TrustLevel) {
        Task {
            do {
                _ = try await dependencyContainer.trustService.updateTrustLevel(peerId: peerId, trustLevel: level)
                await loadPeers()
            } catch {
                await MainActor.run {
                    errorMessage = error.localizedDescription
                    showError = true
                }
            }
        }
    }

    private func endorsePeer(peerId: String, level: TrustLevel) {
        guard let endorserId = appState.currentIdentity?.id else {
            errorMessage = "Local identity is not ready yet"
            showError = true
            return
        }

        Task {
            do {
                _ = try await dependencyContainer.trustService.endorsePeer(
                    peerId: peerId,
                    by: endorserId,
                    trustLevel: level
                )
                await loadPeers()
            } catch {
                await MainActor.run {
                    errorMessage = error.localizedDescription
                    showError = true
                }
            }
        }
    }

    private func removePeer(peerId: String) {
        Task {
            do {
                try await dependencyContainer.trustService.removePeer(peerId: peerId)
                await loadPeers()
            } catch {
                await MainActor.run {
                    errorMessage = error.localizedDescription
                    showError = true
                }
            }
        }
    }

    private func copyPairingCode() {
        #if os(macOS)
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(pairingCode, forType: .string)
        #elseif canImport(UIKit)
        UIPasteboard.general.string = pairingCode
        #endif
    }
}

// MARK: - Peer Row

private struct PeerRow: View {
    let peer: PeerIdentity
    let onTrustChange: (TrustLevel) -> Void
    let onEndorse: (TrustLevel) -> Void
    let onRemove: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            Circle()
                .fill(TrustBadge.color(for: peer.trustLevel).opacity(0.2))
                .frame(width: 40, height: 40)
                .overlay {
                    Text(peer.displayName.prefix(1))
                        .font(.headline)
                        .foregroundColor(TrustBadge.color(for: peer.trustLevel))
                }

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(peer.displayName)
                        .font(.subheadline)
                        .fontWeight(.semibold)

                    TrustBadge(level: peer.trustLevel)
                }

                Text("Fingerprint \(peer.publicKeyFingerprint.prefix(12))")
                    .font(.caption)
                    .foregroundColor(.secondary)

                if !peer.verificationMethods.isEmpty {
                    Text("Verified: \(methodSummary)")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }

                if !peer.endorsements.isEmpty {
                    Text("Endorsements: \(peer.endorsements.count)")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }

            Spacer()
        }
        .contextMenu {
            Menu("Set Trust Level") {
                ForEach(TrustLevel.allCases) { level in
                    Button(level.title) {
                        onTrustChange(level)
                    }
                }
            }

            Menu("Add Endorsement") {
                Button("Endorse as Trusted") {
                    onEndorse(.trusted)
                }
                Button("Endorse as Highly Trusted") {
                    onEndorse(.highlyTrusted)
                }
            }

            Button("Remove Peer", role: .destructive) {
                onRemove()
            }
        }
    }

    private var methodSummary: String {
        peer.verificationMethods.map { $0.title }.joined(separator: ", ")
    }
}

// MARK: - Trust Badge

private struct TrustBadge: View {
    let level: TrustLevel

    var body: some View {
        Text(level.title)
            .font(.caption2)
            .fontWeight(.semibold)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Self.color(for: level).opacity(0.2))
            .foregroundColor(Self.color(for: level))
            .clipShape(Capsule())
    }

    static func color(for level: TrustLevel) -> Color {
        switch level {
        case .untrusted:
            return .red
        case .caution:
            return .orange
        case .trusted:
            return .green
        case .highlyTrusted:
            return .blue
        }
    }
}

#Preview {
    NavigationStack {
        TrustNetworkView()
            .environmentObject(AppState())
            .environmentObject(AppDependencyContainer())
    }
}
