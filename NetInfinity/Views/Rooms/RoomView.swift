//
//  RoomView.swift
//  NetInfinity
//
//

import SwiftUI

// MARK: - Room View

struct RoomView: View {
    let roomId: String
    
    @EnvironmentObject var navigationManager: NavigationManager
    @EnvironmentObject var dependencyContainer: AppDependencyContainer
    
    @StateObject private var viewModel: RoomViewModel
    @State private var showRoomDetails = false
    @State private var showMemberList = false
    @State private var showSearch = false
    @State private var scrollProxy: ScrollViewProxy?
    
    private let roomService: RoomService
    
    init(roomId: String, roomService: RoomService) {
        self.roomId = roomId
        self.roomService = roomService
        _viewModel = StateObject(wrappedValue: RoomViewModel(roomId: roomId, roomService: roomService))
    }
    
    var body: some View {
        VStack(spacing: 0) {
            // Room header
            roomHeader
            
            // Message timeline
            messageTimeline
            
            // Message composer
            messageComposer
        }
        .platformNavigationBarHidden(true)
        .background(Color(.systemBackground))
        .sheet(isPresented: $showRoomDetails) {
            RoomDetailsView(roomId: roomId, roomService: roomService)
                .environmentObject(navigationManager)
                .environmentObject(dependencyContainer)
        }
        .sheet(isPresented: $showMemberList) {
            RoomMemberListView(roomId: roomId, roomService: roomService)
                .environmentObject(navigationManager)
                .environmentObject(dependencyContainer)
        }
        .sheet(isPresented: $showSearch) {
            RoomSearchView(roomId: roomId, roomService: roomService)
                .environmentObject(navigationManager)
                .environmentObject(dependencyContainer)
        }
        .onAppear {
            Task {
                await viewModel.loadRoomDetails()
                await viewModel.loadMessages()
            }
        }
    }
    
    // MARK: - Subviews
    
    private var roomHeader: some View {
        HStack(spacing: 12) {
            // Back button
            backButton
            
            // Room info
            roomInfo
            
            // Actions
            headerActions
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
        .background(Color(.systemBackground))
        .shadow(color: Color(.systemGray4), radius: 1, y: 1)
    }
    
    private var backButton: some View {
        Button(action: { 
            navigationManager.navigateBack()
        }) {
            Image(systemName: "chevron.left")
                .font(.title2)
                .foregroundColor(.primary)
        }
    }
    
    private var roomInfo: some View {
        HStack(spacing: 8) {
            // Room avatar
            if let room = viewModel.room {
                ZStack {
                    if let avatarUrl = room.avatarUrl, let url = URL(string: avatarUrl) {
                        AsyncImage(url: url) { image in
                            image
                                .resizable()
                                .aspectRatio(contentMode: .fill)
                        } placeholder: {
                            roomAvatarPlaceholder(for: room)
                        }
                    } else {
                        roomAvatarPlaceholder(for: room)
                    }
                }
                .frame(width: 36, height: 36)
                .cornerRadius(8)
            } else {
                ProgressView()
                    .frame(width: 36, height: 36)
            }
            
            // Room name and status
            VStack(alignment: .leading, spacing: 2) {
                if let room = viewModel.room {
                    Text(room.displayName)
                        .font(.headline)
                        .fontWeight(.semibold)
                        .lineLimit(1)
                    
                    if let topic = room.topic, !topic.isEmpty {
                        Text(topic)
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                    } else {
                        Text("Online")
                            .font(.caption)
                            .foregroundColor(.green)
                    }
                } else {
                    Text("Loading...")
                        .font(.headline)
                        .foregroundColor(.secondary)
                    
                    ProgressView()
                        .scaleEffect(0.5)
                }
            }
        }
    }
    
    private func roomAvatarPlaceholder(for room: Room) -> some View {
        ZStack {
            if room.isDirect {
                Color.blue
            } else if room.isSpace {
                Color.purple
            } else {
                Color(.systemGray5)
            }
            
            if room.isDirect, let firstChar = room.name?.first {
                Text(String(firstChar))
                    .font(.headline)
                    .fontWeight(.bold)
                    .foregroundColor(.white)
            } else {
                Image(systemName: room.isSpace ? "folder.fill" : "bubble.left.fill")
                    .font(.subheadline)
                    .foregroundColor(.white)
            }
        }
    }
    
    private var headerActions: some View {
        HStack(spacing: 16) {
            // Search
            Button(action: { 
                showSearch = true
            }) {
                Image(systemName: "magnifyingglass")
                    .font(.subheadline)
                    .foregroundColor(.primary)
            }
            
            // Members
            Button(action: { 
                showMemberList = true
            }) {
                Image(systemName: "person.2")
                    .font(.subheadline)
                    .foregroundColor(.primary)
            }
            
            // Room details
            Button(action: { 
                showRoomDetails = true
            }) {
                Image(systemName: "info.circle")
                    .font(.subheadline)
                    .foregroundColor(.primary)
            }
        }
    }
    
    private var messageTimeline: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 8) {
                    // Loading indicator for older messages
                    if viewModel.isLoadingOlderMessages {
                        ProgressView()
                            .padding()
                            .onAppear {
                                Task {
                                    await viewModel.loadOlderMessages()
                                }
                            }
                    }
                    
                    // Messages
                    ForEach(viewModel.messages) { message in
                        MessageBubbleView(message: message)
                            .id(message.id)
                            .transition(.opacity)
                    }
                    
                    // Typing indicators
                    if viewModel.isTyping {
                        typingIndicator
                    }
                }
                .padding(.horizontal)
                .padding(.top, 8)
                .padding(.bottom, 72) // Space for composer
            }
            .onChange(of: viewModel.messages.count) { _ in
                // Scroll to bottom when new messages arrive
                if let lastMessage = viewModel.messages.last {
                    withAnimation {
                        proxy.scrollTo(lastMessage.id, anchor: .bottom)
                    }
                }
            }
            .onAppear {
                self.scrollProxy = proxy
                // Scroll to bottom on initial load
                if let lastMessage = viewModel.messages.last {
                    withAnimation {
                        proxy.scrollTo(lastMessage.id, anchor: .bottom)
                    }
                }
            }
        }
    }
    
    private var typingIndicator: some View {
        HStack(spacing: 4) {
            Circle()
                .frame(width: 8, height: 8)
                .foregroundColor(.gray)
                .scaleEffect(viewModel.typingAnimation ? 1.0 : 0.5)
                .animation(.easeInOut(duration: 0.6).repeatForever(), value: viewModel.typingAnimation)
            
            Circle()
                .frame(width: 8, height: 8)
                .foregroundColor(.gray)
                .scaleEffect(viewModel.typingAnimation ? 1.0 : 0.5)
                .animation(.easeInOut(duration: 0.6).repeatForever().delay(0.2), value: viewModel.typingAnimation)
            
            Circle()
                .frame(width: 8, height: 8)
                .foregroundColor(.gray)
                .scaleEffect(viewModel.typingAnimation ? 1.0 : 0.5)
                .animation(.easeInOut(duration: 0.6).repeatForever().delay(0.4), value: viewModel.typingAnimation)
        }
        .padding(8)
        .background(Color(.systemGray6))
        .cornerRadius(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 8)
        .onAppear {
            viewModel.startTypingAnimation()
        }
        .onDisappear {
            viewModel.stopTypingAnimation()
        }
    }
    
    private var messageComposer: some View {
        MessageComposerView(
            onSendMessage: { content in
                Task {
                    await sendMessage(content)
                }
            },
            onAttachment: { type in
                // Handle attachment
            }
        )
        .padding(.horizontal)
        .padding(.vertical, 8)
        .background(Color(.systemBackground))
        .shadow(color: Color(.systemGray4), radius: 1, y: -1)
    }
    
    // MARK: - Actions
    
    private func sendMessage(_ content: MessageContent) async {
        do {
            let message = try await viewModel.sendMessage(content: content)
            // Scroll to the new message
            if let proxy = scrollProxy, let lastMessage = viewModel.messages.last {
                withAnimation {
                    proxy.scrollTo(lastMessage.id, anchor: .bottom)
                }
            }
        } catch {
            // Handle error
        }
    }
}

// MARK: - Room View Model

final class RoomViewModel: ObservableObject {
    let roomId: String
    
    @Published var room: Room?
    @Published var messages: [Message] = []
    @Published var isLoading = false
    @Published var isLoadingOlderMessages = false
    @Published var isTyping = false
    @Published var typingAnimation = false
    @Published var error: Error?
    
    private let roomService: RoomService
    private var typingTimer: Timer?
    
    init(roomId: String, roomService: RoomService) {
        self.roomId = roomId
        self.roomService = roomService
    }
    
    // MARK: - Data Loading
    
    @MainActor
    func loadRoomDetails() async {
        isLoading = true
        error = nil
        
        do {
            room = try await roomService.getRoom(roomId: roomId)
            isLoading = false
        } catch {
            isLoading = false
            self.error = error
        }
    }
    
    @MainActor
    func loadMessages() async {
        isLoading = true
        error = nil
        
        do {
            messages = try await roomService.getMessages(roomId: roomId, limit: 50, from: nil)
            isLoading = false
        } catch {
            isLoading = false
            self.error = error
        }
    }
    
    @MainActor
    func loadOlderMessages() async {
        guard !isLoadingOlderMessages, let oldestMessage = messages.first else { return }
        
        isLoadingOlderMessages = true
        
        do {
            let olderMessages = try await roomService.getMessages(
                roomId: roomId,
                limit: 30,
                from: oldestMessage.id
            )
            
            if !olderMessages.isEmpty {
                messages.insert(contentsOf: olderMessages, at: 0)
            }
            
            isLoadingOlderMessages = false
        } catch {
            isLoadingOlderMessages = false
            self.error = error
        }
    }
    
    // MARK: - Messaging
    
    @MainActor
    func sendMessage(content: MessageContent) async throws -> Message {
        do {
            let message = try await roomService.sendMessage(roomId: roomId, content: content)
            messages.append(message)
            return message
        } catch {
            self.error = error
            throw error
        }
    }
    
    // MARK: - Typing Animation
    
    func startTypingAnimation() {
        typingAnimation = true
        
        typingTimer = Timer.scheduledTimer(withTimeInterval: 3.0, repeats: false) { _ in
            self.typingAnimation = false
        }
    }
    
    func stopTypingAnimation() {
        typingTimer?.invalidate()
        typingTimer = nil
        typingAnimation = false
    }
}

// MARK: - Message Bubble View

struct MessageBubbleView: View {
    let message: Message

    private static let byteCountFormatter: ByteCountFormatter = {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .file
        return formatter
    }()
    
    var body: some View {
        HStack(spacing: 8) {
            if !message.isFromCurrentUser {
                // Avatar for incoming messages
                if let avatarUrl = message.senderAvatarUrl, let url = URL(string: avatarUrl) {
                    AsyncImage(url: url) { image in
                        image
                            .resizable()
                            .aspectRatio(contentMode: .fill)
                    } placeholder: {
                        Circle()
                            .fill(Color(.systemGray4))
                            .frame(width: 32, height: 32)
                    }
                    .frame(width: 32, height: 32)
                    .cornerRadius(16)
                } else {
                    Circle()
                        .fill(messageBubbleColor(for: message))
                        .frame(width: 32, height: 32)
                        .overlay {
                            Text(message.senderName?.first?.uppercased() ?? "?")
                                .font(.subheadline)
                                .fontWeight(.bold)
                                .foregroundColor(.white)
                        }
                }
            } else {
                // Spacer for outgoing messages
                Color.clear
                    .frame(width: 40)
            }
            
            // Message content
            messageContent
            
            if message.isFromCurrentUser {
                // Status for outgoing messages
                messageStatus
            } else {
                // Spacer for incoming messages
                Color.clear
                    .frame(width: 40)
            }
        }
        .padding(.vertical, 4)
    }
    
    private var messageContent: some View {
        VStack(alignment: message.isFromCurrentUser ? .trailing : .leading, spacing: 4) {
            // Sender name for group rooms
            if !message.isFromCurrentUser {
                Text(message.senderName ?? "Unknown")
                    .font(.caption)
                    .fontWeight(.medium)
                    .foregroundColor(message.isFromCurrentUser ? .white : .primary)
            }
            
            // Message bubble
            messageBubble
            
            // Reactions and replies
            if !message.reactions.isEmpty || (message.replies?.isEmpty == false) {
                messageReactions
            }
        }
    }
    
    private var messageBubble: some View {
        Group {
            switch message.content {
            case .text(let text):
                Text(text)
                    .padding(12)
                    .background(messageBubbleColor(for: message))
                    .foregroundColor(messageTextColor(for: message))
                    .cornerRadius(16)
                    .contextMenu {
                        messageContextMenu
                    }
            
            case .emote(let text):
                Text("* \(text) *")
                    .italic()
                    .padding(12)
                    .background(messageBubbleColor(for: message))
                    .foregroundColor(messageTextColor(for: message))
                    .cornerRadius(16)
                    .contextMenu {
                        messageContextMenu
                    }
            
            case .notice(let text):
                Text(text)
                    .font(.caption)
                    .padding(8)
                    .background(Color(.systemGray5))
                    .foregroundColor(.secondary)
                    .cornerRadius(8)
            
            case .image(let url, let thumbnailUrl, _, _, _):
                messageImage(url: url, thumbnailUrl: thumbnailUrl)
            
            case .video(let url, let thumbnailUrl, _, _, _, _):
                messageVideo(url: url, thumbnailUrl: thumbnailUrl)
            
            case .file(let url, let name, let size, _):
                messageFile(url: url, name: name, size: size)
            
            case .audio(let url, let name, let duration, _, _):
                messageAudio(url: url, name: name, duration: duration)
            
            case .location(let latitude, let longitude, let name):
                messageLocation(latitude: latitude, longitude: longitude, name: name)
            
            case .voiceRecording(let url, let duration, let waveform):
                messageVoiceRecording(url: url, duration: duration, waveform: waveform)
            
            case .poll(let question, let options, let allowsMultiple):
                messagePoll(question: question, options: options, allowsMultiple: allowsMultiple)
            
            case .sticker(let url, let name):
                messageSticker(url: url, name: name)
            
            case .custom:
                Text("Unsupported message type")
                    .font(.caption)
                    .padding(8)
                    .background(Color(.systemGray5))
                    .foregroundColor(.secondary)
                    .cornerRadius(8)
            }
        }
        .frame(maxWidth: 300, alignment: message.isFromCurrentUser ? .trailing : .leading)
    }
    
    private func messageImage(url: String, thumbnailUrl: String?) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            if let thumbnailUrl = thumbnailUrl, let thumbUrl = URL(string: thumbnailUrl) {
                AsyncImage(url: thumbUrl) { image in
                    image
                        .resizable()
                        .aspectRatio(contentMode: .fit)
                        .cornerRadius(12)
                        .onTapGesture {
                            // Show full image
                        }
                } placeholder: {
                    ProgressView()
                        .frame(width: 200, height: 200)
                }
            } else if let imageUrl = URL(string: url) {
                AsyncImage(url: imageUrl) { image in
                    image
                        .resizable()
                        .aspectRatio(contentMode: .fit)
                        .cornerRadius(12)
                        .onTapGesture {
                            // Show full image
                        }
                } placeholder: {
                    ProgressView()
                        .frame(width: 200, height: 200)
                }
            }
            
            if message.isFromCurrentUser {
                Text("📷 Photo")
                    .font(.caption)
                    .foregroundColor(.white)
                    .padding(.horizontal, 4)
                    .padding(.vertical, 2)
                    .background(Color.black.opacity(0.5))
                    .cornerRadius(4)
            }
        }
        .background(messageBubbleColor(for: message))
        .cornerRadius(16)
        .contextMenu {
            messageContextMenu
        }
    }
    
    private func messageVideo(url: String, thumbnailUrl: String?) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            if let thumbnailUrl = thumbnailUrl, let thumbUrl = URL(string: thumbnailUrl) {
                ZStack(alignment: .center) {
                    AsyncImage(url: thumbUrl) { image in
                        image
                            .resizable()
                            .aspectRatio(contentMode: .fit)
                            .cornerRadius(12)
                    } placeholder: {
                        ProgressView()
                            .frame(width: 200, height: 200)
                    }
                    
                    Image(systemName: "play.circle.fill")
                        .font(.title)
                        .foregroundColor(.white)
                }
                .onTapGesture {
                    // Play video
                }
            }
            
            if message.isFromCurrentUser {
                Text("🎥 Video")
                    .font(.caption)
                    .foregroundColor(.white)
                    .padding(.horizontal, 4)
                    .padding(.vertical, 2)
                    .background(Color.black.opacity(0.5))
                    .cornerRadius(4)
            }
        }
        .background(messageBubbleColor(for: message))
        .cornerRadius(16)
        .contextMenu {
            messageContextMenu
        }
    }
    
    private func messageFile(url: String, name: String, size: Int) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "doc.fill")
                    .font(.title2)
                    .foregroundColor(message.isFromCurrentUser ? .white : .blue)
                
                VStack(alignment: .leading, spacing: 4) {
                    Text(name)
                        .font(.subheadline)
                        .fontWeight(.medium)
                        .foregroundColor(message.isFromCurrentUser ? .white : .primary)
                        .lineLimit(1)
                    
                    Text(Self.byteCountFormatter.string(fromByteCount: Int64(size)))
                        .font(.caption)
                        .foregroundColor(message.isFromCurrentUser ? .white.opacity(0.8) : .secondary)
                }
            }
            .padding(12)
            
            Button(action: { 
                // Download file
            }) {
                Text("Download")
                    .font(.subheadline)
                    .fontWeight(.medium)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                    .background(message.isFromCurrentUser ? Color.white.opacity(0.2) : Color.blue.opacity(0.1))
                    .foregroundColor(message.isFromCurrentUser ? .white : .blue)
                    .cornerRadius(8)
            }
            .padding(.horizontal, 12)
            .padding(.bottom, 8)
        }
        .background(messageBubbleColor(for: message))
        .cornerRadius(16)
        .contextMenu {
            messageContextMenu
        }
    }
    
    private func messageAudio(url: String, name: String, duration: Int) -> some View {
        HStack(spacing: 12) {
            Image(systemName: "waveform")
                .font(.title2)
                .foregroundColor(message.isFromCurrentUser ? .white : .blue)
            
            VStack(alignment: .leading, spacing: 4) {
                Text(name)
                    .font(.subheadline)
                    .fontWeight(.medium)
                    .foregroundColor(message.isFromCurrentUser ? .white : .primary)
                    .lineLimit(1)
                
                Text(formatDuration(duration))
                    .font(.caption)
                    .foregroundColor(message.isFromCurrentUser ? .white.opacity(0.8) : .secondary)
            }
            
            Button(action: { 
                // Play audio
            }) {
                Image(systemName: "play.fill")
                    .font(.subheadline)
                    .foregroundColor(message.isFromCurrentUser ? .white : .blue)
            }
        }
        .padding(12)
        .background(messageBubbleColor(for: message))
        .cornerRadius(16)
        .contextMenu {
            messageContextMenu
        }
    }
    
    private func messageLocation(latitude: Double, longitude: Double, name: String?) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            if let name = name {
                Text(name)
                    .font(.subheadline)
                    .fontWeight(.medium)
                    .foregroundColor(message.isFromCurrentUser ? .white : .primary)
            }
            
            MapPreviewView(latitude: latitude, longitude: longitude)
                .frame(height: 150)
                .cornerRadius(8)
                .onTapGesture {
                    // Open in maps
                }
        }
        .padding(12)
        .background(messageBubbleColor(for: message))
        .cornerRadius(16)
        .contextMenu {
            messageContextMenu
        }
    }
    
    private func messageVoiceRecording(url: String, duration: Int, waveform: [Double]) -> some View {
        HStack(spacing: 12) {
            Image(systemName: "mic.fill")
                .font(.title2)
                .foregroundColor(message.isFromCurrentUser ? .white : .blue)
            
            VoiceWaveformView(waveform: waveform, duration: duration)
                .frame(height: 30)
            
            Button(action: { 
                // Play voice message
            }) {
                Image(systemName: "play.fill")
                    .font(.subheadline)
                    .foregroundColor(message.isFromCurrentUser ? .white : .blue)
            }
        }
        .padding(12)
        .background(messageBubbleColor(for: message))
        .cornerRadius(16)
        .contextMenu {
            messageContextMenu
        }
    }
    
    private func messagePoll(question: String, options: [String], allowsMultiple: Bool) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(question)
                .font(.subheadline)
                .fontWeight(.medium)
                .foregroundColor(message.isFromCurrentUser ? .white : .primary)
            
            ForEach(options.indices, id: \.self) { index in
                Button(action: { 
                    // Vote for option
                }) {
                    HStack {
                        if allowsMultiple {
                            Image(systemName: "circle")
                                .font(.subheadline)
                                .foregroundColor(message.isFromCurrentUser ? .white : .blue)
                        } else {
                            Image(systemName: "circle")
                                .font(.subheadline)
                                .foregroundColor(message.isFromCurrentUser ? .white : .blue)
                        }
                        
                        Text(options[index])
                            .font(.subheadline)
                            .foregroundColor(message.isFromCurrentUser ? .white : .primary)
                        
                        Spacer()
                        
                        Text("0 votes")
                            .font(.caption)
                            .foregroundColor(message.isFromCurrentUser ? .white.opacity(0.8) : .secondary)
                    }
                    .padding(8)
                    .background(message.isFromCurrentUser ? Color.white.opacity(0.1) : Color.blue.opacity(0.05))
                    .cornerRadius(8)
                }
            }
        }
        .padding(12)
        .background(messageBubbleColor(for: message))
        .cornerRadius(16)
        .contextMenu {
            messageContextMenu
        }
    }
    
    private func messageSticker(url: String, name: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            if let stickerUrl = URL(string: url) {
                AsyncImage(url: stickerUrl) { image in
                    image
                        .resizable()
                        .aspectRatio(contentMode: .fit)
                        .frame(height: 150)
                } placeholder: {
                    ProgressView()
                        .frame(height: 150)
                }
            }
            
            if message.isFromCurrentUser {
                Text("🎨 \(name)")
                    .font(.caption)
                    .foregroundColor(.white)
                    .padding(.horizontal, 4)
                    .padding(.vertical, 2)
                    .background(Color.black.opacity(0.5))
                    .cornerRadius(4)
            }
        }
        .background(messageBubbleColor(for: message))
        .cornerRadius(16)
        .contextMenu {
            messageContextMenu
        }
    }
    
    private var messageStatus: some View {
        VStack(alignment: .trailing, spacing: 4) {
            // Timestamp
            Text(message.timestamp, style: .time)
                .font(.caption)
                .foregroundColor(.secondary)
            
            // Status indicator
            switch message.status {
            case .sending:
                ProgressView()
                    .scaleEffect(0.5)
            case .sent:
                Image(systemName: "checkmark")
                    .font(.caption)
                    .foregroundColor(.gray)
            case .delivered:
                Image(systemName: "checkmark")
                    .font(.caption)
                    .foregroundColor(.blue)
            case .read:
                Image(systemName: "checkmark")
                    .font(.caption)
                    .foregroundColor(.blue)
                    .background(Color.blue)
                    .clipShape(Circle())
            case .failed:
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundColor(.red)
            case .unknown:
                EmptyView()
            }
        }
    }
    
    private var messageReactions: some View {
        HStack(spacing: 4) {
            ForEach(message.reactions, id: \.key) { reaction in
                Button(action: { 
                    // Add reaction
                }) {
                    Text(reaction.key)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 4)
                        .background(Color(.systemGray5))
                        .cornerRadius(12)
                        .overlay {
                            if reaction.count > 0 {
                                Text(" \(reaction.count)")
                                    .font(.caption2)
                                    .foregroundColor(.white)
                                    .padding(.horizontal, 4)
                                    .padding(.vertical, 2)
                                    .background(Color.blue)
                                    .cornerRadius(8)
                                    .offset(x: 8, y: -8)
                            }
                        }
                }
                .buttonStyle(.plain)
            }
            
            if let replyCount = message.replies?.count, replyCount > 0 {
                Button(action: { 
                    // Show replies
                }) {
                    HStack(spacing: 4) {
                        Image(systemName: "arrowshape.turn.up.left")
                            .font(.caption)
                        Text(" \(replyCount)")
                            .font(.caption)
                    }
                    .padding(.horizontal, 6)
                    .padding(.vertical, 4)
                    .background(Color(.systemGray5))
                    .cornerRadius(12)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.top, 4)
    }
    
    private var messageContextMenu: some View {
        Group {
            Button(action: { 
                // Copy message
            }) {
                Label("Copy", systemImage: "doc.on.doc")
            }
            
            Button(action: { 
                // Reply
            }) {
                Label("Reply", systemImage: "arrowshape.turn.up.left")
            }
            
            Button(action: { 
                // React
            }) {
                Label("React", systemImage: "plus.message")
            }
            
            Button(action: { 
                // Forward
            }) {
                Label("Forward", systemImage: "arrowshape.turn.up.right")
            }
            
            if message.isFromCurrentUser {
                Button(action: { 
                    // Edit
                }) {
                    Label("Edit", systemImage: "pencil")
                }
                
                Button(action: { 
                    // Delete
                }) {
                    Label("Delete", systemImage: "trash")
                }
            } else {
                Button(action: { 
                    // Report
                }) {
                    Label("Report", systemImage: "exclamationmark.triangle")
                }
            }
        }
    }
    
    // MARK: - Helper Methods
    
    private func messageBubbleColor(for message: Message) -> Color {
        return message.isFromCurrentUser ? .blue : Color(.systemGray5)
    }
    
    private func messageTextColor(for message: Message) -> Color {
        return message.isFromCurrentUser ? .white : .primary
    }
    
    private func formatDuration(_ seconds: Int) -> String {
        let minutes = seconds / 60
        let remainingSeconds = seconds % 60
        return String(format: "%d:%02d", minutes, remainingSeconds)
    }
}

// MARK: - Map Preview View

struct MapPreviewView: View {
    let latitude: Double
    let longitude: Double
    
    var body: some View {
        ZStack {
            Color(.systemGray6)
                .cornerRadius(8)
            
            Image(systemName: "map.fill")
                .font(.title)
                .foregroundColor(.blue)
            
            VStack {
                Text("Map Preview")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Text("Lat: \(latitude, specifier: "%.4f")")
                    .font(.caption2)
                    .foregroundColor(.secondary)
                Text("Lon: \(longitude, specifier: "%.4f")")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
    }
}

// MARK: - Voice Waveform View

struct VoiceWaveformView: View {
    let waveform: [Double]
    let duration: Int
    
    var body: some View {
        GeometryReader { geometry in
            HStack(spacing: 2) {
                ForEach(0..<min(waveform.count, 50), id: \.self) { index in
                    Rectangle()
                        .fill(Color.blue)
                        .frame(width: 2, height: CGFloat(waveform[index]) * geometry.size.height)
                        .cornerRadius(1)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

// MARK: - Message Composer View

struct MessageComposerView: View {
    @State private var messageText = ""
    @State private var isRecording = false
    @State private var recordingTime: TimeInterval = 0
    @State private var recordingTimer: Timer?
    @State private var showAttachmentOptions = false
    
    let onSendMessage: (MessageContent) -> Void
    let onAttachment: (AttachmentType) -> Void
    
    var body: some View {
        VStack(spacing: 0) {
            // Main input area
            HStack(spacing: 8) {
                // Attachment button
                if messageText.isEmpty && !isRecording {
                    attachmentButton
                }
                
                // Text input or recording indicator
                if isRecording {
                    recordingIndicator
                } else {
                    textInputField
                }
                
                // Send button
                if !messageText.isEmpty || isRecording {
                    sendButton
                }
            }
            .padding(8)
            .background(Color(.systemGray6))
            .cornerRadius(20)
        }
        .padding(.vertical, 4)
        .sheet(isPresented: $showAttachmentOptions) {
            AttachmentPickerView(onSelect: onAttachment)
        }
    }
    
    private var attachmentButton: some View {
        Button(action: { 
            showAttachmentOptions = true
        }) {
            Image(systemName: "plus.circle.fill")
                .font(.title2)
                .foregroundColor(.blue)
        }
    }
    
    private var textInputField: some View {
        TextField("Type a message...", text: $messageText, axis: .vertical)
            .textFieldStyle(.plain)
            .padding(.vertical, 8)
            .frame(minHeight: 40)
            .onSubmit {
                sendMessage()
            }
    }
    
    private var recordingIndicator: some View {
        HStack(spacing: 8) {
            Image(systemName: "mic.fill")
                .font(.subheadline)
                .foregroundColor(.red)
            
            Text(formatTime(recordingTime))
                .font(.subheadline)
                .fontWeight(.medium)
                .foregroundColor(.primary)
            
            Spacer()
            
            Button(action: { 
                stopRecording()
            }) {
                Image(systemName: "stop.fill")
                    .font(.subheadline)
                    .foregroundColor(.red)
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 8)
    }
    
    private var sendButton: some View {
        Button(action: { 
            if isRecording {
                stopRecording()
            } else {
                sendMessage()
            }
        }) {
            if isRecording {
                Image(systemName: "stop.fill")
                    .font(.title2)
                    .foregroundColor(.red)
            } else {
                Image(systemName: "paperplane.fill")
                    .font(.title2)
                    .foregroundColor(.blue)
            }
        }
    }
    
    // MARK: - Actions
    
    private func sendMessage() {
        guard !messageText.isEmpty else { return }
        
        let content = MessageContent.text(messageText)
        onSendMessage(content)
        messageText = ""
    }
    
    private func startRecording() {
        isRecording = true
        recordingTime = 0
        
        recordingTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in
            recordingTime += 1
        }
    }
    
    private func stopRecording() {
        recordingTimer?.invalidate()
        recordingTimer = nil
        isRecording = false
        recordingTime = 0
    }
    
    private func formatTime(_ time: TimeInterval) -> String {
        let minutes = Int(time) / 60
        let seconds = Int(time) % 60
        return String(format: "%02d:%02d", minutes, seconds)
    }
}

// MARK: - Preview

#Preview {
    RoomView(roomId: "room-preview", roomService: AppDependencyContainer().roomService)
        .environmentObject(NavigationManager())
        .environmentObject(AppDependencyContainer())
}
