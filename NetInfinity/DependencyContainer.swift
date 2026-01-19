//
//  DependencyContainer.swift
//  NetInfinity
//
//

import Foundation

// MARK: - Dependency Injection Container

protocol DependencyContainer {
    var authenticationService: AuthenticationService { get }
    var identityService: IdentityService { get }
    var trustService: TrustService { get }
    var roomService: RoomService { get }
    var messageService: MessageService { get }
    var userService: UserService { get }
    var mediaService: MediaService { get }
    var notificationService: NotificationServiceProtocol { get }
    var analyticsService: AnalyticsService { get }
}

// MARK: - App Dependency Container

final class AppDependencyContainer: ObservableObject, DependencyContainer {
    let authenticationService: AuthenticationService
    let identityService: IdentityService
    let trustService: TrustService
    let roomService: RoomService
    let messageService: MessageService
    let userService: UserService
    let mediaService: MediaService
    let notificationService: NotificationServiceProtocol
    let analyticsService: AnalyticsService
    
    init() {
        // Initialize services with their dependencies
        let networkService = DefaultNetworkService()
        let storageService = DefaultStorageService()
        let keychainService = DefaultKeychainService()
        
        self.authenticationService = DefaultAuthenticationService(
            networkService: networkService,
            storageService: storageService
        )
        
        self.identityService = DefaultIdentityService(
            storageService: storageService,
            keychainService: keychainService
        )

        self.trustService = DefaultTrustService(storageService: storageService)
        
        self.roomService = DefaultRoomService(
            storageService: storageService,
            identityService: self.identityService
        )
        
        self.messageService = DefaultMessageService(roomService: self.roomService)
        
        self.userService = DefaultUserService(
            networkService: networkService,
            storageService: storageService
        )
        
        self.mediaService = DefaultMediaService(
            networkService: networkService,
            storageService: storageService
        )
        
        self.notificationService = NotificationService()
        self.analyticsService = DefaultAnalyticsService()
    }
}

// MARK: - Service Protocols

protocol MessageService {
    func getMessages(roomId: String, limit: Int, from: String?) async throws -> [Message]
    func sendMessage(roomId: String, content: MessageContent) async throws -> Message
    func sendMediaMessage(roomId: String, media: MediaAttachment) async throws -> Message
    func reactToMessage(messageId: String, reaction: String) async throws
}

protocol UserService {
    func getUserProfile(userId: String) async throws -> UserProfile
    func updateUserProfile(profile: UserProfile) async throws -> UserProfile
    func searchUsers(query: String) async throws -> [User]
}

protocol MediaService {
    func uploadMedia(data: Data, filename: String, mimeType: String) async throws -> MediaAttachment
    func downloadMedia(url: URL) async throws -> Data
    func getMediaThumbnail(url: URL) async throws -> Data
}

protocol AnalyticsService {
    func track(event: AnalyticsEvent)
    func setUserProperties(_ properties: [String: Any])
    func logError(_ error: Error)
}

// MARK: - Default Service Implementations

final class DefaultMessageService: MessageService {
    private let roomService: RoomService
    
    init(roomService: RoomService) {
        self.roomService = roomService
    }
    
    func getMessages(roomId: String, limit: Int, from: String?) async throws -> [Message] {
        try await roomService.getMessages(roomId: roomId, limit: limit, from: from)
    }
    
    func sendMessage(roomId: String, content: MessageContent) async throws -> Message {
        try await roomService.sendMessage(roomId: roomId, content: content)
    }
    
    func sendMediaMessage(roomId: String, media: MediaAttachment) async throws -> Message {
        throw AppError.unknownError
    }
    
    func reactToMessage(messageId: String, reaction: String) async throws {
        throw AppError.unknownError
    }
}

final class DefaultUserService: UserService {
    private let networkService: NetworkService
    private let storageService: StorageService
    
    init(networkService: NetworkService, storageService: StorageService) {
        self.networkService = networkService
        self.storageService = storageService
    }
    
    func getUserProfile(userId: String) async throws -> UserProfile {
        throw AppError.unknownError
    }
    
    func updateUserProfile(profile: UserProfile) async throws -> UserProfile {
        throw AppError.unknownError
    }
    
    func searchUsers(query: String) async throws -> [User] {
        throw AppError.unknownError
    }
}

final class DefaultMediaService: MediaService {
    private let networkService: NetworkService
    private let storageService: StorageService
    
    init(networkService: NetworkService, storageService: StorageService) {
        self.networkService = networkService
        self.storageService = storageService
    }
    
    func uploadMedia(data: Data, filename: String, mimeType: String) async throws -> MediaAttachment {
        throw AppError.unknownError
    }
    
    func downloadMedia(url: URL) async throws -> Data {
        throw AppError.unknownError
    }
    
    func getMediaThumbnail(url: URL) async throws -> Data {
        throw AppError.unknownError
    }
}

final class DefaultAnalyticsService: AnalyticsService {
    func track(event: AnalyticsEvent) {
        print("Analytics event: \(event.rawValue)")
    }
    
    func setUserProperties(_ properties: [String : Any]) {
        print("Analytics user properties: \(properties)")
    }
    
    func logError(_ error: Error) {
        print("Analytics error: \(error)")
    }
}

// MARK: - Supporting Services

protocol NetworkService {
    func get<T: Decodable>(_ path: String) async throws -> T
    func get<T: Decodable>(_ path: String, queryParams: [String: String]) async throws -> T
    func post<T: Decodable, Body: Encodable>(_ path: String, body: Body) async throws -> T
    func postVoid<Body: Encodable>(_ path: String, body: Body) async throws
    func post(_ path: String) async throws
    func put<T: Decodable, Body: Encodable>(_ path: String, body: Body) async throws -> T
    func upload<T: Decodable>(_ path: String, data: Data, filename: String, mimeType: String) async throws -> T
    func download(_ url: URL) async throws -> Data
}

protocol StorageService {
    func get<T: Decodable>(_ key: String) async throws -> T?
    func set<T: Encodable>(_ key: String, value: T) async throws
    func remove(_ key: String) throws
    func saveUserPreferences(_ preferences: UserPreferences)
    func getUserPreferences() -> UserPreferences
}

// MARK: - Models

struct User: Identifiable, Codable {
    let id: String
    let username: String
    let displayName: String
    let avatarUrl: String?
    let presence: UserPresence
}

struct UserProfile: Codable {
    let userId: String
    let displayName: String
    let avatarUrl: String?
    let bio: String?
    let status: String?
}

struct MediaAttachment: Codable {
    let id: String
    let url: URL
    let thumbnailUrl: URL?
    let mimeType: String
    let size: Int
    let width: Int?
    let height: Int?
}

struct UserPreferences: Codable {
    var theme: ThemePreference
    var notificationSettings: NotificationSettings
    var privacySettings: PrivacySettings
}

enum ThemePreference: String, Codable {
    case system
    case light
    case dark
}

// MARK: - Enums

enum UserPresence: String, Codable {
    case online
    case away
    case busy
    case offline
}

enum AnalyticsEvent: String {
    case appLaunch
    case loginSuccess
    case loginFailure
    case messageSent
    case roomJoined
    case mediaUploaded
    case errorOccurred
}

// MARK: - Default Implementations

final class DefaultNetworkService: NetworkService {
    func get<T>(_ path: String) async throws -> T where T : Decodable {
        throw AppError.networkError(NSError(domain: "not implemented", code: 501))
    }
    
    func get<T>(_ path: String, queryParams: [String : String]) async throws -> T where T : Decodable {
        throw AppError.networkError(NSError(domain: "not implemented", code: 501))
    }
    
    func post<T, Body>(_ path: String, body: Body) async throws -> T where T : Decodable, Body : Encodable {
        throw AppError.networkError(NSError(domain: "not implemented", code: 501))
    }
    
    func postVoid<Body>(_ path: String, body: Body) async throws where Body : Encodable {
        throw AppError.networkError(NSError(domain: "not implemented", code: 501))
    }
    
    func post(_ path: String) async throws {
        throw AppError.networkError(NSError(domain: "not implemented", code: 501))
    }
    
    func put<T, Body>(_ path: String, body: Body) async throws -> T where T : Decodable, Body : Encodable {
        throw AppError.networkError(NSError(domain: "not implemented", code: 501))
    }
    
    func upload<T>(_ path: String, data: Data, filename: String, mimeType: String) async throws -> T where T : Decodable {
        throw AppError.networkError(NSError(domain: "not implemented", code: 501))
    }
    
    func download(_ url: URL) async throws -> Data {
        throw AppError.networkError(NSError(domain: "not implemented", code: 501))
    }
}

final class DefaultStorageService: StorageService {
    private let defaults: UserDefaults
    
    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }
    
    func get<T>(_ key: String) async throws -> T? where T : Decodable {
        guard let data = defaults.data(forKey: key) else { return nil }
        return try JSONDecoder().decode(T.self, from: data)
    }
    
    func set<T>(_ key: String, value: T) async throws where T : Encodable {
        let data = try JSONEncoder().encode(value)
        defaults.set(data, forKey: key)
    }
    
    func remove(_ key: String) throws {
        defaults.removeObject(forKey: key)
    }
    
    func saveUserPreferences(_ preferences: UserPreferences) {
        if let data = try? JSONEncoder().encode(preferences) {
            defaults.set(data, forKey: "user_preferences")
        }
    }
    
    func getUserPreferences() -> UserPreferences {
        if let data = defaults.data(forKey: "user_preferences"),
           let preferences = try? JSONDecoder().decode(UserPreferences.self, from: data) {
            return preferences
        }
        return UserPreferences(theme: .system,
                               notificationSettings: NotificationSettings(),
                               privacySettings: PrivacySettings())
    }
}

struct NotificationSettings: Codable {
    var enabled: Bool = true
    var sound: Bool = true
    var vibration: Bool = true
}

struct PrivacySettings: Codable {
    var readReceipts: Bool = true
    var typingIndicators: Bool = true
    var onlineStatus: Bool = true
}
