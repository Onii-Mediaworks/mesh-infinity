//
//  CreateRoomView.swift
//  NetInfinity
//
//

import SwiftUI

// MARK: - Create Room View

struct CreateRoomView: View {
    @EnvironmentObject var navigationManager: NavigationManager
    @StateObject private var viewModel: CreateRoomViewModel
    @Environment(\.dismiss) private var dismiss
    
    init(roomService: RoomService) {
        _viewModel = StateObject(wrappedValue: CreateRoomViewModel(roomService: roomService))
    }
    
    var body: some View {
        NavigationStack {
            Form {
                Section("Room Details") {
                    TextField("Room name", text: $viewModel.name)
                    TextField("Topic (optional)", text: $viewModel.topic)
                }
                
                Section("Participants") {
                    Toggle("Direct message", isOn: $viewModel.isDirect)
                    TextField("Invite users (comma separated)", text: $viewModel.invitedUsers)
                        .platformAutocapitalization(.none)
                        .platformAutocorrectionDisabled(true)
                }
                
                Section {
                    Button("Create Room") {
                        Task { await viewModel.createRoom() }
                    }
                    .disabled(!viewModel.canCreate)
                }
            }
            .navigationTitle("New Room")
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
            .alert("Room Created", isPresented: $viewModel.showSuccess) {
                Button("Open") {
                    dismiss()
                    if let roomId = viewModel.createdRoomId {
                        navigationManager.navigateToRoom(roomId)
                    }
                }
            } message: {
                Text("Your room is ready to chat.")
            }
            .alert("Error", isPresented: $viewModel.showError) {
                Button("OK", role: .cancel) { }
            } message: {
                Text(viewModel.errorMessage ?? "Unable to create room.")
            }
        }
    }
}

// MARK: - View Model

final class CreateRoomViewModel: ObservableObject {
    @Published var name = ""
    @Published var topic = ""
    @Published var isDirect = false
    @Published var invitedUsers = ""
    @Published var showSuccess = false
    @Published var showError = false
    @Published var errorMessage: String?
    @Published var createdRoomId: String?
    
    private let roomService: RoomService
    
    init(roomService: RoomService) {
        self.roomService = roomService
    }
    
    var canCreate: Bool {
        !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
    
    @MainActor
    func createRoom() async {
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty else { return }
        
        let users = invitedUsers
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        
        do {
            let room = try await roomService.createRoom(
                name: trimmedName,
                topic: topic.isEmpty ? nil : topic,
                isDirect: isDirect,
                userIds: users.isEmpty ? nil : users
            )
            createdRoomId = room.id
            showSuccess = true
        } catch {
            errorMessage = "Unable to create room. Try again."
            showError = true
        }
    }
}

#Preview {
    CreateRoomView(roomService: AppDependencyContainer().roomService)
        .environmentObject(NavigationManager())
}
