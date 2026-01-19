//
//  DeepLinkHandlerView.swift
//  NetInfinity
//

import SwiftUI

// MARK: - Deep Link Handler View

struct DeepLinkHandlerView: View {
    let url: URL
    
    @EnvironmentObject var navigationManager: NavigationManager
    
    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "link")
                .font(.largeTitle)
                .foregroundColor(.blue)
            
            Text("Deep Link")
                .font(.title2)
                .fontWeight(.semibold)
            
            Text(url.absoluteString)
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
            
            Button("Return Home") {
                navigationManager.navigateToHome()
            }
            .buttonStyle(.borderedProminent)
        }
        .padding()
        .navigationTitle("Link")
        .platformNavigationBarTitleDisplayMode(.inline)
    }
}

#Preview {
    NavigationStack {
        DeepLinkHandlerView(url: URL(string: "netinfinity://room/123")!)
            .environmentObject(NavigationManager())
    }
}
