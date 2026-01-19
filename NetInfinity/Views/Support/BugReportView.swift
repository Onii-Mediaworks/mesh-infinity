//
//  BugReportView.swift
//  NetInfinity
//

import SwiftUI

// MARK: - Bug Report View

struct BugReportView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var title = ""
    @State private var description = ""
    @State private var includeLogs = true
    
    var body: some View {
        NavigationStack {
            Form {
                Section("Summary") {
                    TextField("Short title", text: $title)
                    TextField("Describe the issue", text: $description, axis: .vertical)
                        .lineLimit(4, reservesSpace: true)
                }
                
                Section("Diagnostics") {
                    Toggle("Include logs", isOn: $includeLogs)
                }
                
                Section {
                    Button("Submit Report") {
                        dismiss()
                    }
                    .disabled(title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
            .navigationTitle("Bug Report")
            .platformNavigationBarTitleDisplayMode(.inline)
            .toolbar {
                #if os(macOS)
                ToolbarItem(placement: .navigation) {
                    Button("Cancel") { dismiss() }
                }
                #else
                ToolbarItem(placement: .topBarLeading) {
                    Button("Cancel") { dismiss() }
                }
                #endif
            }
        }
    }
}

#Preview {
    BugReportView()
}
