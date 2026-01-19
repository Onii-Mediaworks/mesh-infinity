//
//  AttachmentPickerView.swift
//  NetInfinity
//

import SwiftUI

enum AttachmentType: String, CaseIterable, Identifiable {
    case photoLibrary
    case camera
    case document
    case location
    
    var id: String { rawValue }
    
    var title: String {
        switch self {
        case .photoLibrary: return "Photo Library"
        case .camera: return "Take Photo"
        case .document: return "Document"
        case .location: return "Location"
        }
    }
    
    var systemImage: String {
        switch self {
        case .photoLibrary: return "photo.on.rectangle"
        case .camera: return "camera"
        case .document: return "doc"
        case .location: return "location"
        }
    }
}

struct AttachmentPickerView: View {
    let onSelect: (AttachmentType) -> Void
    @Environment(\.dismiss) private var dismiss
    
    var body: some View {
        NavigationStack {
            List {
                ForEach(AttachmentType.allCases) { option in
                    Button(action: {
                        onSelect(option)
                        dismiss()
                    }) {
                        Label(option.title, systemImage: option.systemImage)
                    }
                }
            }
            .navigationTitle("Attach")
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
    AttachmentPickerView { _ in }
}
