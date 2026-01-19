//
//  SettingsView.swift
//  NetInfinity
//
//

import SwiftUI

// MARK: - Settings View

struct SettingsView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var dependencyContainer: AppDependencyContainer
    @AppStorage("settings.nodeMode") private var nodeModeRaw = NodeMode.client.rawValue
    @AppStorage("settings.enableTor") private var enableTor = true
    @AppStorage("settings.enableClearnet") private var enableClearnet = true
    @AppStorage("settings.meshDiscovery") private var meshDiscovery = true
    @AppStorage("settings.meshConfigPath") private var meshConfigPath = ""
    @AppStorage("settings.transportPreference") private var transportPreference = TransportPreference.automatic.rawValue
    @AppStorage("settings.logLevel") private var logLevel = LogLevel.info.rawValue
    @AppStorage("settings.allowRelays") private var allowRelays = true
    @State private var showRegenerateAlert = false
    
    var body: some View {
        List {
            Section {
                identityRow
            }

            Section("Trust & Pairing") {
                NavigationLink {
                    TrustNetworkView()
                } label: {
                    Label("Trust & Pairing", systemImage: "person.3.fill")
                }
            }

            Section("Node Mode") {
                Picker("Mode", selection: $nodeModeRaw) {
                    ForEach(NodeMode.allCases) { mode in
                        Text(mode.title).tag(mode.rawValue)
                    }
                }
                
                Text(nodeMode.description)
                    .font(.footnote)
                    .foregroundColor(.secondary)
            }
            
            Section("Networking") {
                Toggle("Enable Tor", isOn: $enableTor)
                Toggle("Enable Clearnet", isOn: $enableClearnet)
                Toggle("Mesh Discovery", isOn: $meshDiscovery)
                Toggle("Allow Relays", isOn: $allowRelays)
                
                TextField("Mesh config path", text: $meshConfigPath)
                    .platformAutocapitalization(.none)
                    .platformAutocorrectionDisabled(true)
                
                Picker("Transport Priority", selection: $transportPreference) {
                    ForEach(TransportPreference.allCases) { option in
                        Text(option.title).tag(option.rawValue)
                    }
                }
                
                Picker("Log Level", selection: $logLevel) {
                    ForEach(LogLevel.allCases) { level in
                        Text(level.title).tag(level.rawValue)
                    }
                }
            }
            
            Section("Connectivity") {
                statusRow(title: "Mesh Status", value: "Connected", tint: .green)
                statusRow(title: "Active Peers", value: "7")
                statusRow(title: "Preferred Route", value: enableTor ? "Tor" : "Clearnet")
                
                Button("Run Network Diagnostics") {
                    // Hook into diagnostics when networking is wired.
                }
            }
            
            Section("Identity") {
                statusRow(title: "Identity", value: identityStatus)
                statusRow(title: "Public Key", value: publicKeyPreview)
                
                Button("Regenerate Identity", role: .destructive) {
                    showRegenerateAlert = true
                }
            }
        }
        .navigationTitle("Settings")
        .platformNavigationBarTitleDisplayMode(.inline)
        .alert("Regenerate Identity?", isPresented: $showRegenerateAlert) {
            Button("Regenerate", role: .destructive) {
                regenerateIdentity()
            }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text("This will create a new private key and replace your current identity.")
        }
    }

    private var nodeMode: NodeMode {
        NodeMode(rawValue: nodeModeRaw) ?? .client
    }
    
    private var identityRow: some View {
        HStack(spacing: 12) {
            Circle()
                .fill(Color.blue.opacity(0.2))
                .frame(width: 44, height: 44)
                .overlay {
                    Image(systemName: "key.fill")
                        .foregroundColor(.blue)
                        .font(.title2)
                }
            
            VStack(alignment: .leading, spacing: 4) {
                Text(identityDisplayName)
                    .font(.subheadline)
                    .fontWeight(.semibold)
                
                Text(publicKeyPreview)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            
            Spacer()
        }
    }
    
    private var identityDisplayName: String {
        guard let id = appState.currentIdentity?.id else {
            return "Local Identity"
        }
        return "Identity \(id.prefix(12))"
    }
    
    private var identityStatus: String {
        appState.currentIdentity == nil ? "Pending" : "Ready"
    }
    
    private var publicKeyPreview: String {
        guard let key = appState.currentIdentity?.publicKey else {
            return "Generating..."
        }
        let prefix = key.prefix(16)
        return "\(prefix)..."
    }
    
    private func statusRow(title: String, value: String, tint: Color = .secondary) -> some View {
        HStack {
            Text(title)
            Spacer()
            Text(value)
                .foregroundColor(tint)
        }
    }
    
    private func regenerateIdentity() {
        Task {
            do {
                let identity = try await dependencyContainer.identityService.resetIdentity()
                await MainActor.run {
                    appState.setReady(with: identity)
                }
            } catch {
                await MainActor.run {
                    appState.setError(.unknownError)
                }
            }
        }
    }
}

// MARK: - Settings Options

private enum TransportPreference: String, CaseIterable, Identifiable {
    case automatic
    case torFirst
    case clearnetFirst
    case localOnly
    
    var id: String { rawValue }
    
    var title: String {
        switch self {
        case .automatic: return "Automatic"
        case .torFirst: return "Tor First"
        case .clearnetFirst: return "Clearnet First"
        case .localOnly: return "Local Only"
        }
    }
}

private enum LogLevel: String, CaseIterable, Identifiable {
    case error
    case warn
    case info
    case debug
    case trace
    
    var id: String { rawValue }
    
    var title: String {
        rawValue.uppercased()
    }
}

#Preview {
    NavigationStack {
        SettingsView()
            .environmentObject(AppState())
            .environmentObject(AppDependencyContainer())
    }
}
