//
//  NotificationsView.swift
//  NetInfinity
//
//

import SwiftUI

// MARK: - Notifications View

struct NotificationsView: View {
    @State private var notifications: [NotificationItem] = []
    
    var body: some View {
        List {
            if notifications.isEmpty {
                emptyState
            } else {
                ForEach(notifications) { item in
                    NotificationRow(item: item)
                }
            }
        }
        .platformInsetGroupedListStyle()
        .navigationTitle("Alerts")
        .platformNavigationBarTitleDisplayMode(.inline)
    }
    
    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "bell.slash")
                .font(.largeTitle)
                .foregroundColor(.secondary)
            
            Text("No alerts yet")
                .font(.headline)
            
            Text("Mentions, invites, and system updates will appear here.")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 32)
        .listRowBackground(Color.clear)
    }
}

// MARK: - Notification Row

private struct NotificationRow: View {
    let item: NotificationItem
    
    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: item.iconName)
                .font(.title3)
                .foregroundColor(item.tintColor)
                .frame(width: 32, height: 32)
                .background(item.tintColor.opacity(0.12))
                .clipShape(Circle())
            
            VStack(alignment: .leading, spacing: 6) {
                Text(item.title)
                    .font(.subheadline)
                    .fontWeight(.semibold)
                
                Text(item.detail)
                    .font(.caption)
                    .foregroundColor(.secondary)
                
                Text(item.timestamp, style: .relative)
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
            
            Spacer()
        }
        .padding(.vertical, 6)
    }
}

// MARK: - Notification Model

private struct NotificationItem: Identifiable {
    let id = UUID()
    let title: String
    let detail: String
    let timestamp: Date
    let iconName: String
    let tintColor: Color
}

#Preview {
    NavigationStack {
        NotificationsView()
    }
}
