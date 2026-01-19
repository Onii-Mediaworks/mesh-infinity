//
//  RoomService.swift
//  NetInfinity
//
//

import Foundation

// MARK: - Room Service Protocol

protocol RoomService {
    /// Get all rooms for current user
    func getRooms() async throws -> [Room]
    
    /// Get room by ID
    func getRoom(roomId: String) async throws -> Room
    
    /// Create new room
    func createRoom(name: String, topic: String?, isDirect: Bool, userIds: [String]?) async throws -> Room
    
    /// Join room by ID or alias
    func joinRoom(roomIdOrAlias: String) async throws -> Room
    
    /// Leave room
    func leaveRoom(roomId: String) async throws
    
    /// Update room settings
    func updateRoom(roomId: String, name: String?, topic: String?, avatarUrl: String?) async throws -> Room
    
    /// Get room members
    func getRoomMembers(roomId: String) async throws -> [RoomMember]
    
    /// Invite users to room
    func inviteUsers(roomId: String, userIds: [String]) async throws
    
    /// Kick user from room
    func kickUser(roomId: String, userId: String, reason: String?) async throws
    
    /// Ban user from room
    func banUser(roomId: String, userId: String, reason: String?) async throws
    
    /// Get room messages
    func getMessages(roomId: String, limit: Int, from: String?) async throws -> [Message]
    
    /// Send message to room
    func sendMessage(roomId: String, content: MessageContent) async throws -> Message
    
    /// Upload file to room
    func uploadFile(roomId: String, data: Data, filename: String, mimeType: String) async throws -> MediaInfo
    
    /// Get room events
    func getRoomEvents(roomId: String, limit: Int, from: String?) async throws -> [RoomEvent]
    
    /// Search rooms
    func searchRooms(query: String, limit: Int) async throws -> [Room]
}

// MARK: - Room Models

struct Room: Identifiable, Codable, Equatable {
    let id: String
    var name: String?
    let canonicalAlias: String?
    var topic: String?
    var avatarUrl: String?
    let roomType: RoomType
    let isDirect: Bool
    let isSpace: Bool
    let isEncrypted: Bool
    var memberCount: Int
    var unreadCount: Int
    let notificationLevel: NotificationLevel
    var lastMessage: Message?
    var lastActivityTimestamp: Date
    let tags: [RoomTag]
    let joinRule: JoinRule
    let creatorId: String
    var isFavorite: Bool
    var isArchived: Bool
    
    var displayName: String {
        return name ?? canonicalAlias ?? id
    }
    
    var hasUnreadMessages: Bool {
        return unreadCount > 0
    }
}

enum RoomType: String, Codable {
    case room
    case space
    case direct
    case unknown
}

enum NotificationLevel: String, Codable {
    case allMessages
    case mentionsOnly
    case mute
    case unknown
}

enum JoinRule: String, Codable {
    case `public`
    case `private`
    case invite
    case knock
    case restricted
    case unknown
}

struct RoomTag: Codable, Equatable {
    let name: String
    let order: Double?
}

struct RoomMember: Identifiable, Codable, Equatable {
    let id: String
    let roomId: String
    let userId: String
    let displayName: String?
    let avatarUrl: String?
    let membership: MembershipState
    let powerLevel: Int
    let isDefault: Bool
    let joinedAt: Date
}

enum MembershipState: String, Codable {
    case join
    case invite
    case leave
    case ban
    case knock
    case unknown
}

// MARK: - Message Models

struct Message: Identifiable, Codable, Equatable {
    let id: String
    let roomId: String
    let senderId: String
    let senderName: String?
    let senderAvatarUrl: String?
    let content: MessageContent
    let timestamp: Date
    let isEdited: Bool
    let isEncrypted: Bool
    let status: MessageStatus
    let reactions: [Reaction]
    let replies: [Message]?
    let threadId: String?
    
    var isFromCurrentUser: Bool {
        guard let currentUserId = MessageContext.currentUserId else {
            return false
        }
        return senderId == currentUserId
    }
}

enum MessageContext {
    static var currentUserId: String?
}

enum MessageStatus: String, Codable {
    case sending
    case sent
    case delivered
    case read
    case failed
    case unknown
}

enum MessageContent: Codable, Equatable {
    case text(String)
    case emote(String)
    case notice(String)
    case image(url: String, thumbnailUrl: String?, width: Int, height: Int, size: Int)
    case video(url: String, thumbnailUrl: String?, width: Int, height: Int, duration: Int, size: Int)
    case file(url: String, name: String, size: Int, mimeType: String)
    case audio(url: String, name: String, duration: Int, size: Int, mimeType: String)
    case location(latitude: Double, longitude: Double, name: String?)
    case voiceRecording(url: String, duration: Int, waveform: [Double])
    case poll(question: String, options: [String], allowsMultiple: Bool)
    case sticker(url: String, name: String)
    case custom(type: String, content: [String: String])
    
    // Coding keys and encoding/decoding implementation
    private enum CodingKeys: String, CodingKey {
        case type, text, emote, notice, url, thumbnailUrl, width, height, size, 
             latitude, longitude, name, duration, waveform, question, options, 
             allowsMultiple, mimeType
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(String.self, forKey: .type)
        
        switch type {
        case "m.text", "org.matrix.msc1767.text":
            let text = try container.decode(String.self, forKey: .text)
            self = .text(text)
        case "m.emote":
            let text = try container.decode(String.self, forKey: .text)
            self = .emote(text)
        case "m.notice":
            let text = try container.decode(String.self, forKey: .text)
            self = .notice(text)
        case "m.image":
            let url = try container.decode(String.self, forKey: .url)
            let thumbnailUrl = try container.decodeIfPresent(String.self, forKey: .thumbnailUrl)
            let width = try container.decode(Int.self, forKey: .width)
            let height = try container.decode(Int.self, forKey: .height)
            let size = try container.decode(Int.self, forKey: .size)
            self = .image(url: url, thumbnailUrl: thumbnailUrl, width: width, height: height, size: size)
        case "m.video":
            let url = try container.decode(String.self, forKey: .url)
            let thumbnailUrl = try container.decodeIfPresent(String.self, forKey: .thumbnailUrl)
            let width = try container.decode(Int.self, forKey: .width)
            let height = try container.decode(Int.self, forKey: .height)
            let duration = try container.decode(Int.self, forKey: .duration)
            let size = try container.decode(Int.self, forKey: .size)
            self = .video(url: url, thumbnailUrl: thumbnailUrl, width: width, height: height, duration: duration, size: size)
        case "m.file":
            let url = try container.decode(String.self, forKey: .url)
            let name = try container.decode(String.self, forKey: .name)
            let size = try container.decode(Int.self, forKey: .size)
            let mimeType = try container.decode(String.self, forKey: .mimeType)
            self = .file(url: url, name: name, size: size, mimeType: mimeType)
        case "m.audio":
            let url = try container.decode(String.self, forKey: .url)
            let name = try container.decode(String.self, forKey: .name)
            let duration = try container.decode(Int.self, forKey: .duration)
            let size = try container.decode(Int.self, forKey: .size)
            let mimeType = try container.decode(String.self, forKey: .mimeType)
            self = .audio(url: url, name: name, duration: duration, size: size, mimeType: mimeType)
        case "m.location":
            let latitude = try container.decode(Double.self, forKey: .latitude)
            let longitude = try container.decode(Double.self, forKey: .longitude)
            let name = try container.decodeIfPresent(String.self, forKey: .name)
            self = .location(latitude: latitude, longitude: longitude, name: name)
        case "m.sticker":
            let url = try container.decode(String.self, forKey: .url)
            let name = try container.decode(String.self, forKey: .name)
            self = .sticker(url: url, name: name)
        case "m.poll.start":
            let question = try container.decode(String.self, forKey: .question)
            let options = try container.decode([String].self, forKey: .options)
            let allowsMultiple = try container.decodeIfPresent(Bool.self, forKey: .allowsMultiple) ?? false
            self = .poll(question: question, options: options, allowsMultiple: allowsMultiple)
        case "m.voice":
            let url = try container.decode(String.self, forKey: .url)
            let duration = try container.decode(Int.self, forKey: .duration)
            let waveform = try container.decode([Double].self, forKey: .waveform)
            self = .voiceRecording(url: url, duration: duration, waveform: waveform)
        default:
            let contentContainer = try decoder.container(keyedBy: CodingKeys.self)
            var contentDict = [String: String]()
            for key in contentContainer.allKeys {
                if let value = try? contentContainer.decode(String.self, forKey: key) {
                    contentDict[key.stringValue] = value
                } else if let value = try? contentContainer.decode(Int.self, forKey: key) {
                    contentDict[key.stringValue] = String(value)
                } else if let value = try? contentContainer.decode(Bool.self, forKey: key) {
                    contentDict[key.stringValue] = value ? "true" : "false"
                } else if let value = try? contentContainer.decode(Double.self, forKey: key) {
                    contentDict[key.stringValue] = String(value)
                }
            }
            self = .custom(type: type, content: contentDict)
        }
    }
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        switch self {
        case .text(let text):
            try container.encode("m.text", forKey: .type)
            try container.encode(text, forKey: .text)
        case .emote(let text):
            try container.encode("m.emote", forKey: .type)
            try container.encode(text, forKey: .text)
        case .notice(let text):
            try container.encode("m.notice", forKey: .type)
            try container.encode(text, forKey: .text)
        case .image(let url, let thumbnailUrl, let width, let height, let size):
            try container.encode("m.image", forKey: .type)
            try container.encode(url, forKey: .url)
            try container.encodeIfPresent(thumbnailUrl, forKey: .thumbnailUrl)
            try container.encode(width, forKey: .width)
            try container.encode(height, forKey: .height)
            try container.encode(size, forKey: .size)
        case .video(let url, let thumbnailUrl, let width, let height, let duration, let size):
            try container.encode("m.video", forKey: .type)
            try container.encode(url, forKey: .url)
            try container.encodeIfPresent(thumbnailUrl, forKey: .thumbnailUrl)
            try container.encode(width, forKey: .width)
            try container.encode(height, forKey: .height)
            try container.encode(duration, forKey: .duration)
            try container.encode(size, forKey: .size)
        case .file(let url, let name, let size, let mimeType):
            try container.encode("m.file", forKey: .type)
            try container.encode(url, forKey: .url)
            try container.encode(name, forKey: .name)
            try container.encode(size, forKey: .size)
            try container.encode(mimeType, forKey: .mimeType)
        case .audio(let url, let name, let duration, let size, let mimeType):
            try container.encode("m.audio", forKey: .type)
            try container.encode(url, forKey: .url)
            try container.encode(name, forKey: .name)
            try container.encode(duration, forKey: .duration)
            try container.encode(size, forKey: .size)
            try container.encode(mimeType, forKey: .mimeType)
        case .location(let latitude, let longitude, let name):
            try container.encode("m.location", forKey: .type)
            try container.encode(latitude, forKey: .latitude)
            try container.encode(longitude, forKey: .longitude)
            try container.encodeIfPresent(name, forKey: .name)
        case .voiceRecording(let url, let duration, let waveform):
            try container.encode("m.voice", forKey: .type)
            try container.encode(url, forKey: .url)
            try container.encode(duration, forKey: .duration)
            try container.encode(waveform, forKey: .waveform)
        case .poll(let question, let options, let allowsMultiple):
            try container.encode("m.poll.start", forKey: .type)
            try container.encode(question, forKey: .question)
            try container.encode(options, forKey: .options)
            try container.encode(allowsMultiple, forKey: .allowsMultiple)
        case .sticker(let url, let name):
            try container.encode("m.sticker", forKey: .type)
            try container.encode(url, forKey: .url)
            try container.encode(name, forKey: .name)
        case .custom(let type, _):
            try container.encode(type, forKey: .type)
            // Custom content encoding would be implemented based on the specific content
        }
    }
}

struct Reaction: Codable, Equatable {
    let key: String
    let count: Int
    let senders: [String]
}

struct MediaInfo: Codable, Equatable {
    let url: String
    let thumbnailUrl: String?
    let mimeType: String
    let size: Int
    let width: Int?
    let height: Int?
    let duration: Int?
}

struct RoomEvent: Codable {
    let id: String
    let roomId: String
    let type: String
    let senderId: String
    let content: [String: String]
    let timestamp: Date
    let stateKey: String?
}

// MARK: - Default Room Service Implementation

final class DefaultRoomService: RoomService {
    private let storageService: StorageService
    private let identityService: IdentityService
    private let store: LocalRoomStore
    private var cachedIdentity: LocalIdentity?
    
    init(storageService: StorageService, identityService: IdentityService) {
        self.storageService = storageService
        self.identityService = identityService
        self.store = LocalRoomStore(storageService: storageService)
    }
    
    // MARK: - Room Management
    
    func getRooms() async throws -> [Room] {
        let rooms = try await store.loadRooms()
        return rooms.sorted { $0.lastActivityTimestamp > $1.lastActivityTimestamp }
    }
    
    func getRoom(roomId: String) async throws -> Room {
        let rooms = try await store.loadRooms()
        guard let room = rooms.first(where: { $0.id == roomId }) else {
            throw AppError.unknownError
        }
        return room
    }
    
    func createRoom(name: String, topic: String?, isDirect: Bool, userIds: [String]?) async throws -> Room {
        let identity = try await currentIdentity()
        let roomId = (isDirect ? "dm-" : "room-") + UUID().uuidString.lowercased()
        let aliasSeed = name.lowerCaseEnglishReplaced
        let roomAlias = isDirect || aliasSeed.isEmpty ? nil : "#" + aliasSeed
        
        let members = buildMembers(
            roomId: roomId,
            creatorId: identity.id,
            invitedUserIds: userIds ?? []
        )
        
        let room = Room(
            id: roomId,
            name: name.isEmpty ? nil : name,
            canonicalAlias: roomAlias,
            topic: topic,
            avatarUrl: nil,
            roomType: isDirect ? .direct : .room,
            isDirect: isDirect,
            isSpace: false,
            isEncrypted: true,
            memberCount: members.count,
            unreadCount: 0,
            notificationLevel: .allMessages,
            lastMessage: nil,
            lastActivityTimestamp: Date(),
            tags: [],
            joinRule: isDirect ? .invite : .private,
            creatorId: identity.id,
            isFavorite: false,
            isArchived: false
        )
        
        var rooms = try await store.loadRooms()
        rooms.insert(room, at: 0)
        try await store.saveRooms(rooms)
        try await store.saveMembers(members, roomId: roomId)
        try await store.saveMessages([], roomId: roomId)
        return room
    }
    
    func joinRoom(roomIdOrAlias: String) async throws -> Room {
        let identity = try await currentIdentity()
        var rooms = try await store.loadRooms()
        
        if let existing = rooms.first(where: { $0.id == roomIdOrAlias || $0.canonicalAlias == roomIdOrAlias }) {
            return existing
        }
        
        let roomId = roomIdOrAlias.hasPrefix("#") ? UUID().uuidString.lowercased() : roomIdOrAlias
        let roomAlias = roomIdOrAlias.hasPrefix("#") ? roomIdOrAlias : nil
        
        let members = buildMembers(roomId: roomId, creatorId: identity.id, invitedUserIds: [])
        let room = Room(
            id: roomId,
            name: nil,
            canonicalAlias: roomAlias,
            topic: nil,
            avatarUrl: nil,
            roomType: .room,
            isDirect: false,
            isSpace: false,
            isEncrypted: true,
            memberCount: members.count,
            unreadCount: 0,
            notificationLevel: .allMessages,
            lastMessage: nil,
            lastActivityTimestamp: Date(),
            tags: [],
            joinRule: .public,
            creatorId: identity.id,
            isFavorite: false,
            isArchived: false
        )
        
        rooms.insert(room, at: 0)
        try await store.saveRooms(rooms)
        try await store.saveMembers(members, roomId: roomId)
        try await store.saveMessages([], roomId: roomId)
        return room
    }
    
    func leaveRoom(roomId: String) async throws {
        var rooms = try await store.loadRooms()
        rooms.removeAll { $0.id == roomId }
        try await store.saveRooms(rooms)
        try await store.removeMessages(roomId: roomId)
        try await store.removeMembers(roomId: roomId)
    }
    
    func updateRoom(roomId: String, name: String?, topic: String?, avatarUrl: String?) async throws -> Room {
        var rooms = try await store.loadRooms()
        guard let index = rooms.firstIndex(where: { $0.id == roomId }) else {
            throw AppError.unknownError
        }
        
        var updated = rooms[index]
        if let name = name {
            updated.name = name
        }
        if let topic = topic {
            updated.topic = topic
        }
        if let avatarUrl = avatarUrl {
            updated.avatarUrl = avatarUrl
        }
        
        rooms[index] = updated
        try await store.saveRooms(rooms)
        return updated
    }
    
    // MARK: - Room Members
    
    func getRoomMembers(roomId: String) async throws -> [RoomMember] {
        return try await store.loadMembers(roomId: roomId)
    }
    
    func inviteUsers(roomId: String, userIds: [String]) async throws {
        guard !userIds.isEmpty else { return }
        var members = try await store.loadMembers(roomId: roomId)
        let existingIds = Set(members.map { $0.userId })
        let newMembers = userIds
            .filter { !existingIds.contains($0) }
            .map { buildMember(roomId: roomId, userId: $0, membership: .invite) }
        
        guard !newMembers.isEmpty else { return }
        members.append(contentsOf: newMembers)
        try await store.saveMembers(members, roomId: roomId)
        try await updateMemberCount(roomId: roomId, count: members.count)
    }
    
    func kickUser(roomId: String, userId: String, reason: String?) async throws {
        try await removeMember(roomId: roomId, userId: userId)
    }
    
    func banUser(roomId: String, userId: String, reason: String?) async throws {
        try await removeMember(roomId: roomId, userId: userId)
    }
    
    // MARK: - Messaging
    
    func getMessages(roomId: String, limit: Int, from: String?) async throws -> [Message] {
        let messages = try await store.loadMessages(roomId: roomId)
        if let from = from, let fromIndex = messages.firstIndex(where: { $0.id == from }) {
            let olderMessages = messages[..<fromIndex]
            let start = max(olderMessages.count - limit, 0)
            return Array(olderMessages[start..<olderMessages.count])
        }
        return Array(messages.suffix(limit))
    }
    
    func sendMessage(roomId: String, content: MessageContent) async throws -> Message {
        let identity = try await currentIdentity()
        
        var messages = try await store.loadMessages(roomId: roomId)
        let message = Message(
            id: UUID().uuidString.lowercased(),
            roomId: roomId,
            senderId: identity.id,
            senderName: nil,
            senderAvatarUrl: nil,
            content: content,
            timestamp: Date(),
            isEdited: false,
            isEncrypted: true,
            status: .sent,
            reactions: [],
            replies: nil,
            threadId: nil
        )
        
        messages.append(message)
        try await store.saveMessages(messages, roomId: roomId)
        try await updateRoomActivity(roomId: roomId, lastMessage: message)
        return message
    }
    
    func uploadFile(roomId: String, data: Data, filename: String, mimeType: String) async throws -> MediaInfo {
        throw AppError.unknownError
    }
    
    // MARK: - Room Events
    
    func getRoomEvents(roomId: String, limit: Int, from: String?) async throws -> [RoomEvent] {
        return []
    }
    
    // MARK: - Search
    
    func searchRooms(query: String, limit: Int) async throws -> [Room] {
        let rooms = try await store.loadRooms()
        guard !query.isEmpty else { return [] }
        let matches = rooms.filter { room in
            room.name?.localizedCaseInsensitiveContains(query) ?? false ||
            room.topic?.localizedCaseInsensitiveContains(query) ?? false ||
            room.id.localizedCaseInsensitiveContains(query) ||
            room.canonicalAlias?.localizedCaseInsensitiveContains(query) ?? false
        }
        return Array(matches.prefix(limit))
    }
    
    private func currentIdentity() async throws -> LocalIdentity {
        if let cachedIdentity = cachedIdentity {
            return cachedIdentity
        }
        let identity = try await identityService.loadOrCreateIdentity()
        cachedIdentity = identity
        MessageContext.currentUserId = identity.id
        return identity
    }
    
    private func updateRoomActivity(roomId: String, lastMessage: Message) async throws {
        var rooms = try await store.loadRooms()
        guard let index = rooms.firstIndex(where: { $0.id == roomId }) else { return }
        rooms[index].lastMessage = lastMessage
        rooms[index].lastActivityTimestamp = Date()
        rooms[index].unreadCount = 0
        try await store.saveRooms(rooms)
    }
    
    private func updateMemberCount(roomId: String, count: Int) async throws {
        var rooms = try await store.loadRooms()
        guard let index = rooms.firstIndex(where: { $0.id == roomId }) else { return }
        rooms[index].memberCount = count
        try await store.saveRooms(rooms)
    }
    
    private func removeMember(roomId: String, userId: String) async throws {
        var members = try await store.loadMembers(roomId: roomId)
        members.removeAll { $0.userId == userId }
        try await store.saveMembers(members, roomId: roomId)
        try await updateMemberCount(roomId: roomId, count: members.count)
    }
    
    private func buildMembers(roomId: String, creatorId: String, invitedUserIds: [String]) -> [RoomMember] {
        var members = [buildMember(roomId: roomId, userId: creatorId, membership: .join)]
        for userId in invitedUserIds {
            members.append(buildMember(roomId: roomId, userId: userId, membership: .invite))
        }
        return members
    }
    
    private func buildMember(roomId: String, userId: String, membership: MembershipState) -> RoomMember {
        RoomMember(
            id: UUID().uuidString.lowercased(),
            roomId: roomId,
            userId: userId,
            displayName: nil,
            avatarUrl: nil,
            membership: membership,
            powerLevel: membership == .join ? 100 : 0,
            isDefault: membership == .join,
            joinedAt: Date()
        )
    }
}

// MARK: - Request Models

private actor LocalRoomStore {
    private let storageService: StorageService
    private let roomsKey = "rooms.store.v1"
    private let messagesPrefix = "rooms.messages.v1."
    private let membersPrefix = "rooms.members.v1."
    
    init(storageService: StorageService) {
        self.storageService = storageService
    }
    
    func loadRooms() async throws -> [Room] {
        return try await storageService.get(roomsKey) ?? []
    }
    
    func saveRooms(_ rooms: [Room]) async throws {
        try await storageService.set(roomsKey, value: rooms)
    }
    
    func loadMessages(roomId: String) async throws -> [Message] {
        return try await storageService.get(messagesPrefix + roomId) ?? []
    }
    
    func saveMessages(_ messages: [Message], roomId: String) async throws {
        try await storageService.set(messagesPrefix + roomId, value: messages)
    }
    
    func removeMessages(roomId: String) async throws {
        try storageService.remove(messagesPrefix + roomId)
    }
    
    func loadMembers(roomId: String) async throws -> [RoomMember] {
        return try await storageService.get(membersPrefix + roomId) ?? []
    }
    
    func saveMembers(_ members: [RoomMember], roomId: String) async throws {
        try await storageService.set(membersPrefix + roomId, value: members)
    }
    
    func removeMembers(roomId: String) async throws {
        try storageService.remove(membersPrefix + roomId)
    }
}

extension String {
    var lowerCaseEnglishReplaced: String {
        return self.lowercased()
            .replacingOccurrences(of: " ", with: "_")
            .replacingOccurrences(of: "[^a-z0-9_]", with: "", options: .regularExpression)
    }
}
