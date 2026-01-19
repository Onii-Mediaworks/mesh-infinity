//
//  AccountSelectView.swift
//  NetInfinity
//

import SwiftUI

// MARK: - Account Select View

struct AccountSelectView: View {
    let currentSessionId: String
    let intent: Intent?
    let permalinkData: PermalinkData?
    
    @Environment(\.dismiss) private var dismiss
    @State private var selectedSessionId: String
    
    private let availableSessions: [String] = []
    
    init(currentSessionId: String, intent: Intent?, permalinkData: PermalinkData?) {
        self.currentSessionId = currentSessionId
        self.intent = intent
        self.permalinkData = permalinkData
        _selectedSessionId = State(initialValue: currentSessionId)
    }
    
    var body: some View {
        List {
            Section("Current Session") {
                Text(currentSessionId)
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }
            
            Section("Available Accounts") {
                if availableSessions.isEmpty {
                    Text("No other accounts available.")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                } else {
                    ForEach(availableSessions, id: \.self) { session in
                        HStack {
                            Text(session)
                            Spacer()
                            if session == selectedSessionId {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(.blue)
                            }
                        }
                        .contentShape(Rectangle())
                        .onTapGesture {
                            selectedSessionId = session
                        }
                    }
                }
            }
            
            if intent?.url != nil || permalinkData != nil {
                Section("Pending Action") {
                    Text(intent?.url?.absoluteString ?? "Incoming link")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }
        .platformInsetGroupedListStyle()
        .navigationTitle("Select Account")
        .platformNavigationBarTitleDisplayMode(.inline)
        .toolbar {
            #if os(macOS)
            ToolbarItem(placement: .navigation) {
                Button("Done") { dismiss() }
            }
            #else
            ToolbarItem(placement: .topBarLeading) {
                Button("Done") { dismiss() }
            }
            #endif
        }
    }
}

#Preview {
    NavigationStack {
        AccountSelectView(currentSessionId: "session-alpha", intent: nil, permalinkData: nil)
    }
}
