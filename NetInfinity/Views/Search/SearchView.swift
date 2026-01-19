//
//  SearchView.swift
//  NetInfinity
//
//

import SwiftUI

// MARK: - Search View

struct SearchView: View {
    @EnvironmentObject var navigationManager: NavigationManager
    @StateObject private var viewModel: SearchViewModel
    @State private var query = ""
    @State private var isSearching = false
    
    init(roomService: RoomService) {
        _viewModel = StateObject(wrappedValue: SearchViewModel(roomService: roomService))
    }
    
    var body: some View {
        VStack(spacing: 12) {
            searchBar
            
            if query.isEmpty {
                emptyState
            } else {
                resultsList
            }
        }
        .navigationTitle("Search")
        .platformNavigationBarTitleDisplayMode(.inline)
        .padding(.top, 8)
        .background(Color(.systemBackground))
    }
    
    private var searchBar: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .foregroundColor(.secondary)
            
            TextField("Search rooms, people, and messages", text: $query)
                .textFieldStyle(.plain)
                .submitLabel(.search)
                .onSubmit {
                    runSearch()
                }
            
            if !query.isEmpty {
                Button(action: {
                    query = ""
                    viewModel.reset()
                }) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(.secondary)
                }
            }
            
            Button(action: runSearch) {
                Text("Go")
                    .font(.subheadline)
            }
            .buttonStyle(.borderedProminent)
            .disabled(query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(Color(.systemGray6))
        .cornerRadius(12)
        .padding(.horizontal)
    }
    
    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "sparkle.magnifyingglass")
                .font(.largeTitle)
                .foregroundColor(.secondary)
            
            Text("Find rooms and people fast")
                .font(.headline)
            
            Text("Search by name, alias, or keyword.")
                .font(.subheadline)
                .foregroundColor(.secondary)
        }
        .padding(.top, 40)
    }
    
    private var resultsList: some View {
        List {
            if isSearching {
                HStack {
                    ProgressView()
                    Text("Searching...")
                        .foregroundColor(.secondary)
                }
            } else if viewModel.results.isEmpty {
                Text("No results found.")
                    .foregroundColor(.secondary)
            } else {
                Section(header: Text("Rooms")) {
                    ForEach(viewModel.results) { room in
                        Button(action: {
                            navigationManager.navigateToRoom(room.id)
                        }) {
                            HStack(spacing: 12) {
                                RoomAvatarView(room: room)
                                
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(room.displayName)
                                        .font(.subheadline)
                                        .fontWeight(.semibold)
                                    
                                    if let topic = room.topic, !topic.isEmpty {
                                        Text(topic)
                                            .font(.caption)
                                            .foregroundColor(.secondary)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        .platformInsetGroupedListStyle()
    }
    
    private func runSearch() {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        
        isSearching = true
        Task {
            await viewModel.search(query: trimmed)
            await MainActor.run {
                isSearching = false
            }
        }
    }
}

// MARK: - Search View Model

final class SearchViewModel: ObservableObject {
    @Published var results: [Room] = []
    
    private let roomService: RoomService
    
    init(roomService: RoomService) {
        self.roomService = roomService
    }
    
    @MainActor
    func search(query: String) async {
        do {
            results = try await roomService.searchRooms(query: query, limit: 50)
        } catch {
            results = []
        }
    }
    
    func reset() {
        results = []
    }
}

// MARK: - Room Avatar

private struct RoomAvatarView: View {
    let room: Room
    
    var body: some View {
        ZStack {
            if let avatarUrl = room.avatarUrl, let url = URL(string: avatarUrl) {
                AsyncImage(url: url) { image in
                    image
                        .resizable()
                        .aspectRatio(contentMode: .fill)
                } placeholder: {
                    placeholder
                }
            } else {
                placeholder
            }
        }
        .frame(width: 44, height: 44)
        .cornerRadius(12)
    }
    
    private var placeholder: some View {
        ZStack {
            if room.isDirect {
                Color.blue
            } else if room.isSpace {
                Color.purple
            } else {
                Color(.systemGray5)
            }
            
            Image(systemName: room.isSpace ? "folder.fill" : "bubble.left.fill")
                .font(.subheadline)
                .foregroundColor(.white)
        }
    }
}

#Preview {
    NavigationStack {
        SearchView(roomService: AppDependencyContainer().roomService)
            .environmentObject(NavigationManager())
    }
}
