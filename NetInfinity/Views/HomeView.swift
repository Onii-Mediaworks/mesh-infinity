//
//  HomeView.swift
//  NetInfinity
//
//

import SwiftUI

// MARK: - Home View

struct HomeView: View {
    let roomService: RoomService
    
    init(roomService: RoomService) {
        self.roomService = roomService
    }
    
    var body: some View {
        #if os(macOS)
        ChatSplitView(roomService: roomService)
        #else
        RoomListView(roomService: roomService)
        #endif
    }
}

// MARK: - Chat Split View (macOS)

#if os(macOS)
struct ChatSplitView: View {
    let roomService: RoomService

    @EnvironmentObject var navigationManager: NavigationManager

    var body: some View {
        NavigationSplitView {
            RoomListView(
                roomService: roomService,
                selectedRoomId: $navigationManager.selectedRoomId
            )
        } detail: {
            if let roomId = navigationManager.selectedRoomId {
                RoomView(roomId: roomId, roomService: roomService)
            } else {
                ChatEmptyStateView()
            }
        }
        .navigationSplitViewStyle(.balanced)
    }
}

// MARK: - Empty Detail State

struct ChatEmptyStateView: View {
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "bubble.left.and.bubble.right")
                .font(.system(size: 48))
                .foregroundColor(.secondary)

            Text("Select a chat")
                .font(.title3)
                .fontWeight(.semibold)

            Text("Choose a room to start messaging.")
                .font(.subheadline)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(.systemBackground))
    }
}
#endif

#Preview {
    HomeView(roomService: AppDependencyContainer().roomService)
        .environmentObject(NavigationManager())
        .environmentObject(AppDependencyContainer())
}
