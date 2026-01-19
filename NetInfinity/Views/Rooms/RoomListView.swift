//
//  RoomListView.swift
//  NetInfinity
//
//

import SwiftUI

// MARK: - Room List View

struct RoomListView: View {
    @EnvironmentObject var navigationManager: NavigationManager
    @EnvironmentObject var dependencyContainer: AppDependencyContainer
    
    @StateObject private var viewModel: RoomListViewModel
    @State private var searchText = ""
    @State private var selectedFilter: RoomFilter = .all
    @State private var showCreateRoom = false
    @Binding private var selectedRoomId: String?
    
    private let roomService: RoomService
    
    init(roomService: RoomService, selectedRoomId: Binding<String?> = .constant(nil)) {
        self.roomService = roomService
        _selectedRoomId = selectedRoomId
        _viewModel = StateObject(wrappedValue: RoomListViewModel(roomService: roomService))
    }
    
    var body: some View {
        ZStack(alignment: .bottomTrailing) {
            VStack(spacing: 0) {
                // Search bar
                searchBar
                
                // Filter buttons
                filterButtons
                
                // Room list
                roomList
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            
            floatingActionButton
        }
        .navigationTitle("Chats")
        .platformNavigationBarTitleDisplayMode(.inline)
        .toolbar {
            #if os(macOS)
            ToolbarItem(placement: .navigation) {
                Button(action: {
                    navigationManager.navigateToSettings()
                }) {
                    Image(systemName: "gear")
                        .imageScale(.large)
                }
            }
            ToolbarItem(placement: .primaryAction) {
                Button(action: {
                    showCreateRoom = true
                }) {
                    Image(systemName: "square.and.pencil")
                        .imageScale(.large)
                }
                .help("Start chat")
            }
            #else
            ToolbarItem(placement: .topBarLeading) {
                Button(action: {
                    navigationManager.navigateToSettings()
                }) {
                    Image(systemName: "gear")
                        .imageScale(.large)
                }
            }
            #endif
        }
        .sheet(isPresented: $showCreateRoom) {
            CreateRoomView(roomService: roomService)
                .environmentObject(navigationManager)
                .environmentObject(dependencyContainer)
        }
        .refreshable {
            await viewModel.loadRooms()
        }
        .onChange(of: searchText) { newValue in
            Task {
                await viewModel.searchRooms(query: newValue)
            }
        }
        .onAppear {
            if viewModel.rooms.isEmpty {
                Task {
                    await viewModel.loadRooms()
                }
            }
        }
        .onChange(of: viewModel.rooms) { newRooms in
            #if os(macOS)
            if selectedRoomId == nil, let firstRoom = newRooms.first {
                selectedRoomId = firstRoom.id
                navigationManager.selectedRoomId = firstRoom.id
            }
            #endif
        }
    }
    
    // MARK: - Subviews
    
    private var searchBar: some View {
        HStack {
            Image(systemName: "magnifyingglass")
                .foregroundColor(.secondary)
                .padding(.leading, 8)
            
            TextField("Search chats and messages", text: $searchText)
                .textFieldStyle(.plain)
                .padding(.vertical, 8)
            
            if !searchText.isEmpty {
                Button(action: { 
                    searchText = ""
                }) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(.secondary)
                        .padding(.trailing, 8)
                }
            }
        }
        .background(Color(.systemGray6))
        .cornerRadius(10)
        .padding(.horizontal)
        .padding(.vertical, 8)
    }
    
    private var filterButtons: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(RoomFilter.allCases, id: \.self) { filter in
                    filterButton(for: filter)
                }
            }
            .padding(.horizontal)
            .padding(.vertical, 8)
        }
    }
    
    private func filterButton(for filter: RoomFilter) -> some View {
        Button(action: { 
            selectedFilter = filter
        }) {
            HStack(spacing: 4) {
                if filter.icon != nil {
                    Image(systemName: filter.icon!)
                }
                Text(filter.title)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(selectedFilter == filter ? Color.blue : Color(.systemGray5))
            .foregroundColor(selectedFilter == filter ? .white : .primary)
            .cornerRadius(20)
            .font(.subheadline)
            .fontWeight(.medium)
        }
        .buttonStyle(.plain)
    }
    
    private var roomList: some View {
        Group {
            if viewModel.isLoading && viewModel.rooms.isEmpty {
                VStack(spacing: 12) {
                    ProgressView()
                    Text("Loading chats...")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Color(.systemBackground))
            } else if viewModel.rooms.isEmpty && !isFiltering {
                RoomListEmptyState {
                    showCreateRoom = true
                }
            } else {
                listView
            }
        }
    }

    private var listView: some View {
        Group {
            #if os(macOS)
            List(selection: $selectedRoomId) {
                listSections
            }
            .listStyle(.sidebar)
            #else
            List {
                listSections
            }
            .platformInsetGroupedListStyle()
            #endif
        }
        .background(Color(.systemBackground))
    }

    @ViewBuilder
    private var listSections: some View {
        if isFiltering {
            if filteredRooms.isEmpty {
                EmptySectionView(title: "No results", subtitle: "Try a different filter or keyword")
            } else {
                Section(header: sectionHeader("Results")) {
                    ForEach(filteredRooms) { room in
                        RoomRowView(room: room)
                            .tag(room.id)
                            .onTapGesture {
                                handleRoomSelection(room.id)
                            }
                    }
                }
            }
        } else {
            // Favorites section
            if viewModel.favoriteRooms.isEmpty {
                EmptySectionView(title: "Favorites", subtitle: "No favorite rooms")
            } else {
                Section(header: sectionHeader("Favorites")) {
                    ForEach(viewModel.favoriteRooms) { room in
                        RoomRowView(room: room)
                            .tag(room.id)
                            .onTapGesture {
                                handleRoomSelection(room.id)
                            }
                    }
                }
            }
            
            // Direct messages section
            if viewModel.directRooms.isEmpty {
                EmptySectionView(title: "Direct Messages", subtitle: "No direct messages")
            } else {
                Section(header: sectionHeader("Direct Messages")) {
                    ForEach(viewModel.directRooms) { room in
                        RoomRowView(room: room)
                            .tag(room.id)
                            .onTapGesture {
                                handleRoomSelection(room.id)
                            }
                    }
                }
            }

            // Spaces section
            if viewModel.spaceRooms.isEmpty {
                EmptySectionView(title: "Spaces", subtitle: "No spaces yet")
            } else {
                Section(header: sectionHeader("Spaces")) {
                    ForEach(viewModel.spaceRooms) { room in
                        RoomRowView(room: room)
                            .tag(room.id)
                            .onTapGesture {
                                handleRoomSelection(room.id)
                            }
                    }
                }
            }
            
            // Rooms section
            if viewModel.regularRooms.isEmpty {
                EmptySectionView(title: "Rooms", subtitle: "No rooms found")
            } else {
                Section(header: sectionHeader("Rooms")) {
                    ForEach(viewModel.regularRooms) { room in
                        RoomRowView(room: room)
                            .tag(room.id)
                            .onTapGesture {
                                handleRoomSelection(room.id)
                            }
                    }
                }
            }
        }
    }
    
    private func sectionHeader(_ title: String) -> some View {
        HStack {
            Text(title)
                .font(.headline)
                .fontWeight(.semibold)
            Spacer()
            if title == "Rooms" {
                Button("See All") { }
                    .font(.subheadline)
                    .foregroundColor(.blue)
            }
        }
    }

    private var floatingActionButton: some View {
        #if os(macOS)
        EmptyView()
        #else
        Button(action: {
            showCreateRoom = true
        }) {
            Image(systemName: "square.and.pencil")
                .font(.title2)
                .foregroundColor(.white)
                .padding(18)
                .background(Color.blue)
                .clipShape(Circle())
                .shadow(color: Color.black.opacity(0.2), radius: 6, x: 0, y: 3)
        }
        .padding(.trailing, 20)
        .padding(.bottom, 24)
        .accessibilityLabel("Start chat")
        #endif
    }

    private var isFiltering: Bool {
        selectedFilter != .all || !searchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
    
    private var filteredRooms: [Room] {
        let base = applyFilter(to: viewModel.rooms)
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !query.isEmpty else { return base }
        
        return base.filter { room in
            if room.displayName.lowercased().contains(query) {
                return true
            }
            if let topic = room.topic, topic.lowercased().contains(query) {
                return true
            }
            if let lastMessage = room.lastMessage {
                switch lastMessage.content {
                case .text(let text), .notice(let text), .emote(let text):
                    return text.lowercased().contains(query)
                default:
                    return false
                }
            }
            return false
        }
    }
    
    private func applyFilter(to rooms: [Room]) -> [Room] {
        switch selectedFilter {
        case .all:
            return rooms
        case .favorites:
            return rooms.filter { $0.isFavorite }
        case .unread:
            return rooms.filter { $0.unreadCount > 0 }
        case .direct:
            return rooms.filter { $0.isDirect }
        case .groups:
            return rooms.filter { !$0.isDirect && !$0.isSpace }
        case .spaces:
            return rooms.filter { $0.isSpace }
        }
    }

    private func handleRoomSelection(_ roomId: String) {
        #if os(macOS)
        selectedRoomId = roomId
        #endif
        navigationManager.navigateToRoom(roomId)
    }
}

// MARK: - Room List View Model

final class RoomListViewModel: ObservableObject {
    @Published var rooms: [Room] = []
    @Published var isLoading = false
    @Published var error: Error?
    
    private let roomService: RoomService
    
    init(roomService: RoomService) {
        self.roomService = roomService
    }
    
    // Computed properties for filtered rooms
    var favoriteRooms: [Room] {
        return rooms.filter { $0.isFavorite && !$0.isDirect }
    }
    
    var directRooms: [Room] {
        return rooms.filter { $0.isDirect }
    }

    var spaceRooms: [Room] {
        return rooms.filter { $0.isSpace }
    }
    
    var regularRooms: [Room] {
        return rooms.filter { !$0.isDirect && !$0.isFavorite && !$0.isSpace }
    }
    
    // MARK: - Data Loading
    
    @MainActor
    func loadRooms() async {
        isLoading = true
        error = nil
        
        do {
            rooms = try await roomService.getRooms()
            isLoading = false
        } catch {
            isLoading = false
            self.error = error
        }
    }
    
    func searchRooms(query: String) async {
        guard !query.isEmpty else {
            await loadRooms()
            return
        }
        
        isLoading = true
        error = nil
        
        do {
            rooms = try await roomService.searchRooms(query: query, limit: 50)
            isLoading = false
        } catch {
            isLoading = false
            self.error = error
        }
    }
}

// MARK: - Room Filter

enum RoomFilter: CaseIterable {
    case all
    case favorites
    case unread
    case direct
    case groups
    case spaces
    
    var title: String {
        switch self {
        case .all: return "All"
        case .favorites: return "Favorites"
        case .unread: return "Unread"
        case .direct: return "Direct"
        case .groups: return "Groups"
        case .spaces: return "Spaces"
        }
    }
    
    var icon: String? {
        switch self {
        case .all: return nil
        case .favorites: return "star.fill"
        case .unread: return "envelope.badge"
        case .direct: return "person.fill"
        case .groups: return "person.3.fill"
        case .spaces: return "folder.fill"
        }
    }
}

// MARK: - Empty Section View

struct EmptySectionView: View {
    let title: String
    let subtitle: String
    
    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: "tray.fill")
                .font(.title)
                .foregroundColor(.secondary)
            
            Text(title)
                .font(.subheadline)
                .fontWeight(.medium)
                .foregroundColor(.secondary)
            
            Text(subtitle)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .center)
        .padding()
        .listRowBackground(Color.clear)
    }
}

// MARK: - Room List Empty State

struct RoomListEmptyState: View {
    let onStartChat: () -> Void
    
    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "bubble.left.and.bubble.right")
                .font(.system(size: 48))
                .foregroundColor(.secondary)
            
            Text("Start your first chat")
                .font(.headline)
            
            Text("Invite someone or create a room to begin.")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
            
            Button(action: onStartChat) {
                Label("Start Chat", systemImage: "square.and.pencil")
                    .font(.subheadline)
            }
            .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}

// MARK: - Room Row View

struct RoomRowView: View {
    let room: Room
    
    var body: some View {
        HStack(spacing: 12) {
            // Avatar
            roomAvatar
            
            // Content
            VStack(alignment: .leading, spacing: 4) {
                roomHeader
                roomPreview
            }
            
            // Metadata
            roomMetadata
        }
        .padding(.vertical, 8)
        .contentShape(Rectangle())
    }
    
    private var roomAvatar: some View {
        ZStack {
            if let avatarUrl = room.avatarUrl, let url = URL(string: avatarUrl) {
                AsyncImage(url: url) { image in
                    image
                        .resizable()
                        .aspectRatio(contentMode: .fill)
                } placeholder: {
                    roomAvatarPlaceholder
                }
            } else {
                roomAvatarPlaceholder
            }
            
            // Unread badge
            if room.hasUnreadMessages {
                unreadBadge
            }
        }
        .frame(width: 50, height: 50)
        .cornerRadius(12)
    }
    
    private var roomAvatarPlaceholder: some View {
        ZStack {
            if room.isDirect {
                Color.blue
            } else if room.isSpace {
                Color.purple
            } else {
                Color(.systemGray5)
            }
            
            if room.isDirect, let firstChar = room.name?.first {
                Text(String(firstChar))
                    .font(.headline)
                    .fontWeight(.bold)
                    .foregroundColor(.white)
            } else {
                Image(systemName: room.isSpace ? "folder.fill" : "bubble.left.fill")
                    .font(.title2)
                    .foregroundColor(.white)
            }
        }
    }
    
    private var unreadBadge: some View {
        ZStack {
            Circle()
                .fill(Color.blue)
                .frame(width: 20, height: 20)
            
            if room.unreadCount > 0 {
                Text(room.unreadCount < 100 ? "\(room.unreadCount)" : "99+")
                    .font(.caption2)
                    .fontWeight(.bold)
                    .foregroundColor(.white)
            }
        }
        .offset(x: 15, y: -15)
    }
    
    private var roomHeader: some View {
        HStack(spacing: 4) {
            Text(room.displayName)
                .font(.subheadline)
                .fontWeight(.semibold)
                .lineLimit(1)
            
            if room.isFavorite {
                Image(systemName: "star.fill")
                    .font(.caption)
                    .foregroundColor(.yellow)
            }
            
            if room.isEncrypted {
                Image(systemName: "lock.fill")
                    .font(.caption)
                    .foregroundColor(.gray)
            }
        }
    }
    
    private var roomPreview: some View {
        HStack(spacing: 4) {
            if let lastMessage = room.lastMessage {
                Text(lastMessagePreview(from: lastMessage))
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                
                if lastMessage.isFromCurrentUser {
                    Image(systemName: "checkmark")
                        .font(.caption)
                        .foregroundColor(lastMessage.status == .read ? .blue : .gray)
                }
            } else {
                Text("No messages yet")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            
            Spacer()
        }
    }
    
    private func lastMessagePreview(from message: Message) -> String {
        switch message.content {
        case .text(let text):
            return text
        case .emote(let text):
            return "* \(text)"
        case .notice(let text):
            return text
        case .image:
            return "📷 Photo"
        case .video:
            return "🎥 Video"
        case .file(let name, _, _, _):
            return "📄 \(name)"
        case .audio:
            return "🎵 Audio"
        case .location:
            return "📍 Location"
        case .voiceRecording:
            return "🎤 Voice Message"
        case .poll(let question, _, _):
            return "🗳️ \(question)"
        case .sticker:
            return "🎨 Sticker"
        case .custom:
            return "Custom message"
        }
    }
    
    private var roomMetadata: some View {
        VStack(alignment: .trailing, spacing: 4) {
            Text(room.lastActivityTimestamp, style: .time)
                .font(.caption)
                .foregroundColor(.secondary)
            
            if room.memberCount > 1 {
                Image(systemName: "person.2.fill")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
    }
}

// MARK: - Preview

#Preview {
    RoomListView(roomService: AppDependencyContainer().roomService)
        .environmentObject(NavigationManager())
        .environmentObject(AppDependencyContainer())
}
