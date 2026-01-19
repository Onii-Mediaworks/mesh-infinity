//
//  MediaViewerView.swift
//  NetInfinity
//
//

import SwiftUI
import AVKit

// MARK: - Media Viewer View

struct MediaViewerView: View {
    let mediaItems: [MediaItem]
    let initialIndex: Int
    
    @EnvironmentObject var navigationManager: NavigationManager
    @State private var currentIndex: Int
    @State private var scale: CGFloat = 1.0
    @State private var offset: CGSize = .zero
    @State private var isZoomed = false
    @State private var showControls = true
    @State private var showCaption = true
    
    init(mediaItems: [MediaItem], initialIndex: Int = 0) {
        self.mediaItems = mediaItems
        self.initialIndex = initialIndex
        self._currentIndex = State(initialValue: initialIndex)
    }
    
    var body: some View {
        ZStack {
            // Background
            Color.black
                .ignoresSafeArea()
            
            // Media content
            TabView(selection: $currentIndex) {
                ForEach(0..<mediaItems.count, id: \.self) { index in
                    mediaContent(for: mediaItems[index])
                        .tag(index)
                }
            }
            #if os(macOS)
            .tabViewStyle(.automatic)
            #else
            .tabViewStyle(.page(indexDisplayMode: .never))
            #endif
            .animation(.easeInOut, value: currentIndex)
            
            // Controls
            if showControls {
                controlsOverlay
            }
        }
        .gesture(
            TapGesture(count: 1)
                .onEnded { _ in
                    withAnimation {
                        showControls.toggle()
                    }
                }
        )
        .gesture(
            TapGesture(count: 2)
                .onEnded { _ in
                    withAnimation {
                        showCaption.toggle()
                    }
                }
        )
        #if !os(macOS)
        .statusBar(hidden: true)
        #endif
        .onAppear {
            // Start with controls visible
            showControls = true
            
            // Auto-hide controls after 3 seconds
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                withAnimation {
                    showControls = false
                }
            }
        }
    }
    
    // MARK: - Subviews
    
    @ViewBuilder
    private func mediaContent(for item: MediaItem) -> some View {
        switch item.type {
        case .image(let url, let thumbnailUrl):
            imageContent(url: url, thumbnailUrl: thumbnailUrl, caption: item.caption)
        case .video(let url, let thumbnailUrl):
            videoContent(url: url, thumbnailUrl: thumbnailUrl, caption: item.caption)
        case .audio(let url):
            audioContent(url: url, caption: item.caption)
        case .document(let url, let name):
            documentContent(url: url, name: name, caption: item.caption)
        }
    }
    
    private func imageContent(url: String, thumbnailUrl: String?, caption: String?) -> some View {
        ZStack {
            // Image with zoom and pan
            if let imageUrl = URL(string: url) {
                AsyncImage(url: imageUrl) { image in
                    image
                        .resizable()
                        .aspectRatio(contentMode: .fit)
                        .scaleEffect(scale)
                        .offset(offset)
                        .gesture(
                            MagnificationGesture()
                                .onChanged { value in
                                    withAnimation {
                                        scale = value.magnitude
                                        isZoomed = value.magnitude > 1.0
                                    }
                                }
                                .onEnded { _ in
                                    withAnimation {
                                        isZoomed = scale > 1.0
                                    }
                                }
                        )
                        .gesture(
                            DragGesture()
                                .onChanged { value in
                                    withAnimation {
                                        offset = value.translation
                                    }
                                }
                                .onEnded { _ in
                                    withAnimation {
                                        // Reset offset when gesture ends
                                        offset = .zero
                                    }
                                }
                        )
                        .onTapGesture(count: 2) {
                            withAnimation {
                                scale = scale > 1.0 ? 1.0 : 2.0
                                isZoomed = scale > 1.0
                            }
                        }
                } placeholder: {
                    if let thumbnailUrl = thumbnailUrl, let thumbUrl = URL(string: thumbnailUrl) {
                        AsyncImage(url: thumbUrl) { image in
                            image
                                .resizable()
                                .aspectRatio(contentMode: .fit)
                        } placeholder: {
                            ProgressView()
                        }
                    } else {
                        ProgressView()
                    }
                }
            } else {
                Color(.systemGray5)
                    .overlay {
                        Image(systemName: "photo")
                            .font(.largeTitle)
                            .foregroundColor(.white)
                    }
            }
            
            // Caption
            if showCaption, let caption = caption, !caption.isEmpty {
                VStack {
                    Spacer()
                    Text(caption)
                        .font(.subheadline)
                        .foregroundColor(.white)
                        .padding()
                        .background(Color.black.opacity(0.7))
                        .cornerRadius(8)
                        .padding(.bottom, 32)
                }
            }
        }
    }
    
    private func videoContent(url: String, thumbnailUrl: String?, caption: String?) -> some View {
        ZStack {
            if let videoUrl = URL(string: url) {
                VideoPlayer(player: AVPlayer(url: videoUrl))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .onAppear {
                        // Auto-play video
                        AVPlayer(url: videoUrl).play()
                    }
            } else if let thumbnailUrl = thumbnailUrl, let thumbUrl = URL(string: thumbnailUrl) {
                AsyncImage(url: thumbUrl) { image in
                    image
                        .resizable()
                        .aspectRatio(contentMode: .fit)
                        .overlay {
                            Image(systemName: "play.circle.fill")
                                .font(.largeTitle)
                                .foregroundColor(.white)
                        }
                } placeholder: {
                    ProgressView()
                }
            } else {
                Color(.systemGray5)
                    .overlay {
                        Image(systemName: "video")
                            .font(.largeTitle)
                            .foregroundColor(.white)
                    }
            }
            
            // Caption
            if showCaption, let caption = caption, !caption.isEmpty {
                VStack {
                    Spacer()
                    Text(caption)
                        .font(.subheadline)
                        .foregroundColor(.white)
                        .padding()
                        .background(Color.black.opacity(0.7))
                        .cornerRadius(8)
                        .padding(.bottom, 32)
                }
            }
        }
    }
    
    private func audioContent(url: String, caption: String?) -> some View {
        VStack(spacing: 24) {
            Spacer()
            
            if let audioUrl = URL(string: url) {
                // Audio player would go here
                VStack(spacing: 16) {
                    Image(systemName: "waveform")
                        .font(.largeTitle)
                        .foregroundColor(.white)
                    
                    Text("Audio Player")
                        .font(.headline)
                        .foregroundColor(.white)
                    
                    Text("Playback controls would be implemented here")
                        .font(.subheadline)
                        .foregroundColor(.white.opacity(0.8))
                }
            } else {
                VStack(spacing: 16) {
                    Image(systemName: "music.note")
                        .font(.largeTitle)
                        .foregroundColor(.white)
                    
                    Text("Audio Unavailable")
                        .font(.headline)
                        .foregroundColor(.white)
                }
            }
            
            Spacer()
            
            // Caption
            if showCaption, let caption = caption, !caption.isEmpty {
                Text(caption)
                    .font(.subheadline)
                    .foregroundColor(.white)
                    .padding()
                    .background(Color.black.opacity(0.7))
                    .cornerRadius(8)
            }
        }
    }
    
    private func documentContent(url: String, name: String, caption: String?) -> some View {
        VStack(spacing: 24) {
            Spacer()
            
            VStack(spacing: 16) {
                Image(systemName: "doc.fill")
                    .font(.largeTitle)
                    .foregroundColor(.white)
                
                Text(name)
                    .font(.headline)
                    .foregroundColor(.white)
                    .lineLimit(2)
                    .multilineTextAlignment(.center)
                
                if let url = URL(string: url) {
                    Button(action: { 
                        // Open document
                    }) {
                        Text("Open Document")
                            .font(.subheadline)
                            .fontWeight(.medium)
                            .padding(.horizontal, 24)
                            .padding(.vertical, 12)
                            .background(Color.blue)
                            .foregroundColor(.white)
                            .cornerRadius(8)
                    }
                }
            }
            
            Spacer()
            
            // Caption
            if showCaption, let caption = caption, !caption.isEmpty {
                Text(caption)
                    .font(.subheadline)
                    .foregroundColor(.white)
                    .padding()
                    .background(Color.black.opacity(0.7))
                    .cornerRadius(8)
            }
        }
    }
    
    private var controlsOverlay: some View {
        VStack {
            // Top controls
            HStack {
                // Close button
                Button(action: { 
                    navigationManager.dismissFullScreenCover()
                }) {
                    Image(systemName: "xmark")
                        .font(.title2)
                        .foregroundColor(.white)
                        .padding()
                        .background(Color.black.opacity(0.6))
                        .cornerRadius(20)
                }
                
                Spacer()
                
                // Media info
                if !mediaItems.isEmpty {
                    Text(" \(currentIndex + 1) of \(mediaItems.count) ")
                        .font(.subheadline)
                        .fontWeight(.medium)
                        .foregroundColor(.white)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .background(Color.black.opacity(0.6))
                        .cornerRadius(20)
                }
            }
            .padding(.top, 48)
            .padding(.horizontal)
            
            Spacer()
            
            // Bottom controls
            HStack(spacing: 32) {
                // Share
                Button(action: { 
                    // Share media
                }) {
                    VStack {
                        Image(systemName: "square.and.arrow.up")
                            .font(.subheadline)
                        Text("Share")
                            .font(.caption)
                    }
                    .foregroundColor(.white)
                    .padding(8)
                }
                
                // Save
                Button(action: { 
                    // Save media
                }) {
                    VStack {
                        Image(systemName: "arrow.down.to.line")
                            .font(.subheadline)
                        Text("Save")
                            .font(.caption)
                    }
                    .foregroundColor(.white)
                    .padding(8)
                }
                
                // Favorite
                Button(action: { 
                    // Toggle favorite
                }) {
                    VStack {
                        Image(systemName: "heart")
                            .font(.subheadline)
                        Text("Favorite")
                            .font(.caption)
                    }
                    .foregroundColor(.white)
                    .padding(8)
                }
                
                // More actions
                Button(action: { 
                    // Show more actions
                }) {
                    VStack {
                        Image(systemName: "ellipsis")
                            .font(.subheadline)
                        Text("More")
                            .font(.caption)
                    }
                    .foregroundColor(.white)
                    .padding(8)
                }
            }
            .padding(.bottom, 48)
        }
    }
}

// MARK: - Media Item Model

struct MediaItem: Identifiable, Equatable {
    let id: String
    let type: MediaType
    let url: String
    let thumbnailUrl: String?
    let caption: String?
    let sender: String
    let timestamp: Date
    let size: Int
    
    enum MediaType: Equatable {
        case image(url: String, thumbnailUrl: String?)
        case video(url: String, thumbnailUrl: String?)
        case audio(url: String)
        case document(url: String, name: String)
    }
}

// MARK: - Preview

#Preview {
    MediaViewerView(mediaItems: [], initialIndex: 0)
        .environmentObject(NavigationManager())
}
