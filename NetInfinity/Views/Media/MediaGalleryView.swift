//
//  MediaGalleryView.swift
//  NetInfinity
//
//

import SwiftUI

// MARK: - Media Gallery View

struct MediaGalleryView: View {
    let mediaItems: [MediaItem]
    let title: String
    let showHeader: Bool
    
    @EnvironmentObject var navigationManager: NavigationManager
    @State private var selectedMedia: MediaItem?
    @State private var selectedIndex: Int?
    
    init(mediaItems: [MediaItem], title: String = "Media Gallery", showHeader: Bool = true) {
        self.mediaItems = mediaItems
        self.title = title
        self.showHeader = showHeader
    }
    
    var body: some View {
        VStack(spacing: 0) {
            // Header
            if showHeader {
                headerView
            }
            
            // Media grid
            mediaGridView
        }
        .background(Color(.systemBackground))
        .navigationTitle(title)
        .platformNavigationBarTitleDisplayMode(.inline)
        #if os(macOS)
        .sheet(item: $selectedMedia) { media in
            if let index = selectedIndex {
                MediaViewerView(mediaItems: mediaItems, initialIndex: index)
                    .environmentObject(navigationManager)
            }
        }
        #else
        .fullScreenCover(item: $selectedMedia) { media in
            if let index = selectedIndex {
                MediaViewerView(mediaItems: mediaItems, initialIndex: index)
                    .environmentObject(navigationManager)
            }
        }
        #endif
    }
    
    // MARK: - Subviews
    
    private var headerView: some View {
        HStack {
            Text(title)
                .font(.headline)
                .fontWeight(.semibold)
            
            Spacer()
            
            if !mediaItems.isEmpty {
                Text(" \(mediaItems.count) items ")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }
        }
        .padding()
        .background(Color(.secondarySystemBackground))
    }
    
    private var mediaGridView: some View {
        ScrollView {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 120), spacing: 4)], spacing: 4) {
                ForEach(mediaItems.indices, id: \.self) { index in
                    let media = mediaItems[index]
                    
                    mediaGridItem(media: media, index: index)
                        .onTapGesture {
                            selectedMedia = media
                            selectedIndex = index
                        }
                }
            }
            .padding(4)
        }
    }
    
    @ViewBuilder
    private func mediaGridItem(media: MediaItem, index: Int) -> some View {
        switch media.type {
        case .image(let url, let thumbnailUrl):
            imageGridItem(url: url, thumbnailUrl: thumbnailUrl, caption: media.caption)
        case .video(let url, let thumbnailUrl):
            videoGridItem(url: url, thumbnailUrl: thumbnailUrl, caption: media.caption)
        case .audio(let url):
            audioGridItem(url: url, caption: media.caption)
        case .document(let url, let name):
            documentGridItem(url: url, name: name, caption: media.caption)
        }
    }
    
    private func imageGridItem(url: String, thumbnailUrl: String?, caption: String?) -> some View {
        ZStack(alignment: .bottomLeading) {
            // Image content
            if let imageUrl = URL(string: url) {
                AsyncImage(url: imageUrl) { image in
                    image
                        .resizable()
                        .aspectRatio(contentMode: .fill)
                        .frame(width: 120, height: 120)
                        .clipped()
                } placeholder: {
                    if let thumbnailUrl = thumbnailUrl, let thumbUrl = URL(string: thumbnailUrl) {
                        AsyncImage(url: thumbUrl) { image in
                            image
                                .resizable()
                                .aspectRatio(contentMode: .fill)
                                .frame(width: 120, height: 120)
                                .clipped()
                        } placeholder: {
                            Color(.systemGray5)
                        }
                    } else {
                        Color(.systemGray5)
                    }
                }
            } else {
                Color(.systemGray5)
            }
            
            // Caption overlay
            if let caption = caption, !caption.isEmpty {
                Text(caption)
                    .font(.caption2)
                    .foregroundColor(.white)
                    .lineLimit(2)
                    .padding(4)
                    .background(Color.black.opacity(0.6))
                    .frame(maxWidth: 120, alignment: .leading)
            }
        }
        .contentShape(Rectangle())
    }
    
    private func videoGridItem(url: String, thumbnailUrl: String?, caption: String?) -> some View {
        ZStack(alignment: .bottomLeading) {
            // Video thumbnail
            if let thumbnailUrl = thumbnailUrl, let thumbUrl = URL(string: thumbnailUrl) {
                AsyncImage(url: thumbUrl) { image in
                    image
                        .resizable()
                        .aspectRatio(contentMode: .fill)
                        .frame(width: 120, height: 120)
                        .clipped()
                        .overlay {
                            Image(systemName: "play.circle.fill")
                                .font(.title)
                                .foregroundColor(.white)
                        }
                } placeholder: {
                    Color(.systemGray5)
                        .overlay {
                            Image(systemName: "video")
                                .font(.title)
                                .foregroundColor(.white)
                        }
                }
            } else {
                Color(.systemGray5)
                    .overlay {
                        Image(systemName: "video")
                            .font(.title)
                            .foregroundColor(.white)
                    }
            }
            
            // Caption overlay
            if let caption = caption, !caption.isEmpty {
                Text(caption)
                    .font(.caption2)
                    .foregroundColor(.white)
                    .lineLimit(2)
                    .padding(4)
                    .background(Color.black.opacity(0.6))
                    .frame(maxWidth: 120, alignment: .leading)
            }
        }
        .contentShape(Rectangle())
    }
    
    private func audioGridItem(url: String, caption: String?) -> some View {
        ZStack(alignment: .bottomLeading) {
            // Audio placeholder
            Color(.systemBlue)
                .frame(width: 120, height: 120)
                .overlay {
                    Image(systemName: "waveform")
                        .font(.largeTitle)
                        .foregroundColor(.white)
                }
            
            // Caption overlay
            if let caption = caption, !caption.isEmpty {
                Text(caption)
                    .font(.caption2)
                    .foregroundColor(.white)
                    .lineLimit(2)
                    .padding(4)
                    .background(Color.black.opacity(0.6))
                    .frame(maxWidth: 120, alignment: .leading)
            }
        }
        .contentShape(Rectangle())
    }
    
    private func documentGridItem(url: String, name: String, caption: String?) -> some View {
        ZStack(alignment: .bottomLeading) {
            // Document placeholder
            Color(.systemGreen)
                .frame(width: 120, height: 120)
                .overlay {
                    VStack {
                        Image(systemName: "doc.fill")
                            .font(.largeTitle)
                            .foregroundColor(.white)
                        
                        Text(name)
                            .font(.caption)
                            .foregroundColor(.white)
                            .lineLimit(2)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, 4)
                    }
                }
            
            // Caption overlay
            if let caption = caption, !caption.isEmpty {
                Text(caption)
                    .font(.caption2)
                    .foregroundColor(.white)
                    .lineLimit(2)
                    .padding(4)
                    .background(Color.black.opacity(0.6))
                    .frame(maxWidth: 120, alignment: .leading)
            }
        }
        .contentShape(Rectangle())
    }
}

// MARK: - Preview

#Preview {
    MediaGalleryView(mediaItems: [])
        .environmentObject(NavigationManager())
}
