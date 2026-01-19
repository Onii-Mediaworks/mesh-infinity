//
//  RoomSearchView.swift
//  NetInfinity
//

import SwiftUI

// MARK: - Room Search View

struct RoomSearchView: View {
    let roomId: String
    
    @Environment(\.dismiss) private var dismiss
    @StateObject private var viewModel: RoomSearchViewModel
    @State private var query = ""
    
    init(roomId: String, roomService: RoomService) {
        self.roomId = roomId
        _viewModel = StateObject(wrappedValue: RoomSearchViewModel(roomId: roomId, roomService: roomService))
    }
    
    var body: some View {
        NavigationStack {
            VStack(spacing: 12) {
                searchBar
                
                List {
                    if viewModel.filteredMessages.isEmpty {
                        emptyState
                    } else {
                        ForEach(viewModel.filteredMessages) { message in
                            VStack(alignment: .leading, spacing: 6) {
                                Text(message.senderName ?? "Unknown")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                
                                Text(previewText(for: message.content))
                                    .font(.subheadline)
                            }
                            .padding(.vertical, 6)
                        }
                    }
                }
                .listStyle(.plain)
            }
            .navigationTitle("Search")
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
            .task {
                await viewModel.loadMessages()
            }
        }
    }
    
    private var searchBar: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .foregroundColor(.secondary)
            TextField("Search in this room", text: $query)
                .textFieldStyle(.plain)
                .onChange(of: query) { _ in
                    viewModel.filterMessages(query: query)
                }
            if !query.isEmpty {
                Button(action: {
                    query = ""
                    viewModel.filterMessages(query: "")
                }) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(Color(.systemGray6))
        .cornerRadius(12)
        .padding(.horizontal)
        .padding(.top, 8)
    }
    
    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "text.magnifyingglass")
                .font(.largeTitle)
                .foregroundColor(.secondary)
            Text("No results")
                .font(.headline)
            Text("Try another keyword or phrase.")
                .font(.subheadline)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 24)
        .listRowBackground(Color.clear)
    }
    
    private func previewText(for content: MessageContent) -> String {
        switch content {
        case .text(let text):
            return text
        case .emote(let text):
            return text
        case .notice(let text):
            return text
        case .image:
            return "Photo"
        case .video:
            return "Video"
        case .file(_, let name, _, _):
            return name
        case .audio(_, let name, _, _, _):
            return name
        case .location:
            return "Location"
        case .voiceRecording:
            return "Voice message"
        case .poll(let question, _, _):
            return question
        case .sticker(_, let name):
            return name
        case .custom:
            return "Custom message"
        }
    }
}

// MARK: - View Model

final class RoomSearchViewModel: ObservableObject {
    let roomId: String
    
    @Published var messages: [Message] = []
    @Published var filteredMessages: [Message] = []
    
    private let roomService: RoomService
    
    init(roomId: String, roomService: RoomService) {
        self.roomId = roomId
        self.roomService = roomService
    }
    
    @MainActor
    func loadMessages() async {
        do {
            let latest = try await roomService.getMessages(roomId: roomId, limit: 100, from: nil)
            messages = latest
            filteredMessages = latest
        } catch {
            messages = []
            filteredMessages = []
        }
    }
    
    func filterMessages(query: String) {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            filteredMessages = messages
            return
        }
        
        let lowercased = trimmed.lowercased()
        filteredMessages = messages.filter { message in
            switch message.content {
            case .text(let text), .emote(let text), .notice(let text):
                return text.lowercased().contains(lowercased)
            case .file(_, let name, _, _), .audio(_, let name, _, _, _), .sticker(_, let name):
                return name.lowercased().contains(lowercased)
            case .poll(let question, _, _):
                return question.lowercased().contains(lowercased)
            default:
                return false
            }
        }
    }
}

#Preview {
    RoomSearchView(roomId: "room-preview", roomService: AppDependencyContainer().roomService)
}
