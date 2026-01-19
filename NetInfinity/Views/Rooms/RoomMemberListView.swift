//
//  RoomMemberListView.swift
//  NetInfinity
//

import SwiftUI

// MARK: - Room Member List View

struct RoomMemberListView: View {
    let roomId: String
    
    @Environment(\.dismiss) private var dismiss
    @StateObject private var viewModel: RoomMemberListViewModel
    
    init(roomId: String, roomService: RoomService) {
        self.roomId = roomId
        _viewModel = StateObject(wrappedValue: RoomMemberListViewModel(roomId: roomId, roomService: roomService))
    }
    
    var body: some View {
        NavigationStack {
            List {
                if viewModel.members.isEmpty {
                    emptyState
                } else {
                    ForEach(viewModel.members) { member in
                        HStack(spacing: 12) {
                            avatar(for: member)
                            VStack(alignment: .leading, spacing: 4) {
                                Text(member.displayName ?? member.userId)
                                    .font(.subheadline)
                                    .fontWeight(.semibold)
                                Text(member.userId)
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            Spacer()
                            Text(member.membership.rawValue.capitalized)
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                        .padding(.vertical, 6)
                    }
                }
            }
            .platformInsetGroupedListStyle()
            .navigationTitle("Members")
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
                await viewModel.loadMembers()
            }
        }
    }
    
    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "person.3.fill")
                .font(.largeTitle)
                .foregroundColor(.secondary)
            Text("No members found")
                .font(.headline)
            Text("Invite people to start the conversation.")
                .font(.subheadline)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 24)
        .listRowBackground(Color.clear)
    }
    
    private func avatar(for member: RoomMember) -> some View {
        ZStack {
            if let avatarUrl = member.avatarUrl, let url = URL(string: avatarUrl) {
                AsyncImage(url: url) { image in
                    image
                        .resizable()
                        .aspectRatio(contentMode: .fill)
                } placeholder: {
                    Circle()
                        .fill(Color(.systemGray4))
                }
            } else {
                Circle()
                    .fill(Color(.systemGray5))
                    .overlay {
                        Text(member.displayName?.first?.uppercased() ?? "?")
                            .font(.subheadline)
                            .fontWeight(.bold)
                            .foregroundColor(.primary)
                    }
            }
        }
        .frame(width: 40, height: 40)
    }
}

// MARK: - View Model

final class RoomMemberListViewModel: ObservableObject {
    let roomId: String
    
    @Published var members: [RoomMember] = []
    @Published var errorMessage: String?
    
    private let roomService: RoomService
    
    init(roomId: String, roomService: RoomService) {
        self.roomId = roomId
        self.roomService = roomService
    }
    
    @MainActor
    func loadMembers() async {
        do {
            members = try await roomService.getRoomMembers(roomId: roomId)
        } catch {
            errorMessage = "Unable to load members."
        }
    }
}

#Preview {
    RoomMemberListView(roomId: "room-preview", roomService: AppDependencyContainer().roomService)
}
