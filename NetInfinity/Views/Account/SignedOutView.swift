//
//  SignedOutView.swift
//  NetInfinity
//

import SwiftUI

// MARK: - Signed Out View

struct SignedOutView: View {
    let sessionId: String
    
    @EnvironmentObject var navigationManager: NavigationManager
    
    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "lock.slash")
                .font(.largeTitle)
                .foregroundColor(.orange)
            
            Text("Signed Out")
                .font(.title2)
                .fontWeight(.semibold)
            
            Text("Session \(sessionId) is no longer active.")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
            
            Button("Return to Login") {
                navigationManager.navigateToLogin()
            }
            .buttonStyle(.borderedProminent)
        }
        .padding()
        .navigationTitle("Signed Out")
        .platformNavigationBarTitleDisplayMode(.inline)
    }
}

#Preview {
    SignedOutView(sessionId: "session-alpha")
        .environmentObject(NavigationManager())
}
