//
//  RoomDetailsView.swift
//  NetInfinity
//

import SwiftUI

// MARK: - Room Details View

struct RoomDetailsView: View {
    let roomId: String
    
    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject var navigationManager: NavigationManager
    @StateObject private var viewModel: RoomDetailsViewModel
    @State private var notificationsEnabled = true
    @State private var isFavorite = false
    @State private var isMuted = false
    @State private var showMembers = false
    @State private var showSearch = false
    
    private let roomService: RoomService
    
    init(roomId: String, roomService: RoomService) {
        self.roomId = roomId
        self.roomService = roomService
        _viewModel = StateObject(wrappedValue: RoomDetailsViewModel(roomId: roomId, roomService: roomService))
    }
    
    var body: some View {
        NavigationStack {
            List {
                Section {
                    roomHeader
                }
                
                Section("Preferences") {
                    Toggle("Notifications", isOn: $notificationsEnabled)
                    Toggle("Favorite", isOn: $isFavorite)
                    Toggle("Mute", isOn: $isMuted)
                }
                
                Section("Room") {
                    infoRow(title: "Room ID", value: roomId)
                    infoRow(title: "Members", value: "\(viewModel.room?.memberCount ?? 0)")
                    infoRow(title: "Encrypted", value: viewModel.room?.isEncrypted == true ? "Yes" : "No")
                }
                
                Section {
                    Button("View Members") {
                        showMembers = true
                    }
                    
                    Button("Search Messages") {
                        showSearch = true
                    }
                    
                    Button("Leave Room") {
                        Task { await viewModel.leaveRoom() }
                    }
                    .foregroundColor(.red)
                }
            }
            .platformInsetGroupedListStyle()
            .navigationTitle("Room Details")
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
            .sheet(isPresented: $showMembers) {
                RoomMemberListView(roomId: roomId, roomService: roomService)
                    .environmentObject(navigationManager)
            }
            .sheet(isPresented: $showSearch) {
                RoomSearchView(roomId: roomId, roomService: roomService)
                    .environmentObject(navigationManager)
            }
            .task {
                await viewModel.loadRoom()
                if let room = viewModel.room {
                    isFavorite = room.isFavorite
                    isMuted = room.notificationLevel == .mute
                }
            }
        }
    }
    
    private var roomHeader: some View {
        HStack(spacing: 12) {
            ZStack {
                if let avatarUrl = viewModel.room?.avatarUrl, let url = URL(string: avatarUrl) {
                    AsyncImage(url: url) { image in
                        image.resizable()
                            .aspectRatio(contentMode: .fill)
                    } placeholder: {
                        avatarPlaceholder
                    }
                } else {
                    avatarPlaceholder
                }
            }
            .frame(width: 56, height: 56)
            .cornerRadius(14)
            
            VStack(alignment: .leading, spacing: 6) {
                Text(viewModel.room?.displayName ?? "Room")
                    .font(.headline)
                    .fontWeight(.semibold)
                
                Text(viewModel.room?.topic ?? "No topic set")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            
            Spacer()
        }
        .padding(.vertical, 8)
    }
    
    private var avatarPlaceholder: some View {
        ZStack {
            Color(.systemGray5)
            Image(systemName: "bubble.left.fill")
                .font(.title2)
                .foregroundColor(.white)
        }
    }
    
    private func infoRow(title: String, value: String) -> some View {
        HStack {
            Text(title)
            Spacer()
            Text(value)
                .foregroundColor(.secondary)
        }
    }
}

// MARK: - Room Details View Model

final class RoomDetailsViewModel: ObservableObject {
    let roomId: String
    
    @Published var room: Room?
    @Published var errorMessage: String?
    
    private let roomService: RoomService
    
    init(roomId: String, roomService: RoomService) {
        self.roomId = roomId
        self.roomService = roomService
    }
    
    @MainActor
    func loadRoom() async {
        do {
            room = try await roomService.getRoom(roomId: roomId)
        } catch {
            errorMessage = "Unable to load room details."
        }
    }
    
    @MainActor
    func leaveRoom() async {
        do {
            try await roomService.leaveRoom(roomId: roomId)
        } catch {
            errorMessage = "Unable to leave room."
        }
    }
}

#Preview {
    RoomDetailsView(roomId: "room-preview", roomService: AppDependencyContainer().roomService)
        .environmentObject(NavigationManager())
}
