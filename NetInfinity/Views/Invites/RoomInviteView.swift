//
//  RoomInviteView.swift
//  NetInfinity
//

import SwiftUI

// MARK: - Room Invite View

struct RoomInviteView: View {
    let roomId: String
    
    @Environment(\.dismiss) private var dismiss
    @State private var hasJoined = false
    
    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "envelope.open.fill")
                .font(.largeTitle)
                .foregroundColor(.blue)
            
            Text("Room Invitation")
                .font(.title2)
                .fontWeight(.semibold)
            
            Text("You have been invited to join \(roomId).")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
            
            HStack(spacing: 12) {
                Button("Decline") {
                    dismiss()
                }
                .buttonStyle(.bordered)
                
                Button(hasJoined ? "Joined" : "Accept") {
                    hasJoined = true
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding()
        .navigationTitle("Invite")
        .platformNavigationBarTitleDisplayMode(.inline)
    }
}

#Preview {
    RoomInviteView(roomId: "room-preview")
}
