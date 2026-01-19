//
//  MediaViewerScreen.swift
//  NetInfinity
//

import SwiftUI

// MARK: - Media Viewer Screen

struct MediaViewerScreen: View {
    let mediaId: String
    
    var body: some View {
        ZStack {
            Color.black
                .ignoresSafeArea()

            VStack(spacing: 12) {
                Image(systemName: "photo.on.rectangle.angled")
                    .font(.system(size: 44))
                    .foregroundColor(.white.opacity(0.8))

                Text("Media unavailable")
                    .font(.headline)
                    .foregroundColor(.white)

                Text("This media item hasn't been loaded yet.")
                    .font(.subheadline)
                    .foregroundColor(.white.opacity(0.7))
            }
            .padding()
        }
    }
}

#Preview {
    MediaViewerScreen(mediaId: "media-1")
        .environmentObject(NavigationManager())
}
