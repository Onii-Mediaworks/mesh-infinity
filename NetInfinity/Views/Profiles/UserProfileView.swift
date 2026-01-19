//
//  UserProfileView.swift
//  NetInfinity
//

import SwiftUI

// MARK: - User Profile View

struct UserProfileView: View {
    let userId: String
    
    @Environment(\.dismiss) private var dismiss
    @State private var isFollowing = false
    @State private var isBlocked = false
    
    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                header
                actionButtons
                detailsCard
            }
            .padding()
        }
        .navigationTitle("Profile")
        .platformNavigationBarTitleDisplayMode(.inline)
        .toolbar {
            #if os(macOS)
            ToolbarItem(placement: .primaryAction) {
                Button("Close") { dismiss() }
            }
            #else
            ToolbarItem(placement: .topBarTrailing) {
                Button("Close") { dismiss() }
            }
            #endif
        }
    }
    
    private var header: some View {
        VStack(spacing: 12) {
            Circle()
                .fill(Color.blue.opacity(0.2))
                .frame(width: 88, height: 88)
                .overlay {
                    Text(String(userId.prefix(1)).uppercased())
                        .font(.largeTitle)
                        .fontWeight(.bold)
                        .foregroundColor(.blue)
                }
            
            Text(userId)
                .font(.headline)
        }
    }
    
    private var actionButtons: some View {
        HStack(spacing: 12) {
            Button(action: { isFollowing.toggle() }) {
                Text(isFollowing ? "Following" : "Follow")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            
            Button(action: { isBlocked.toggle() }) {
                Text(isBlocked ? "Blocked" : "Block")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .tint(.red)
        }
    }
    
    private var detailsCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Details")
                .font(.headline)

            Text("Profile details will appear here once loaded.")
                .font(.subheadline)
                .foregroundColor(.secondary)
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(16)
    }
}

#Preview {
    NavigationStack {
        UserProfileView(userId: "user-preview")
    }
}
