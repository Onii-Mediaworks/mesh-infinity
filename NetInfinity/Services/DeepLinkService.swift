//
//  DeepLinkService.swift
//  NetInfinity
//
//

import Foundation
import Combine

// MARK: - Deep Link Service Protocol

protocol DeepLinkServiceProtocol {
    var deepLinkReceived: PassthroughSubject<DeepLinkData, Never> { get }
    
    func handleDeepLink(url: URL) -> Bool
    func handleUniversalLink(url: URL) -> Bool
    func processDeepLinkData(_ data: DeepLinkData)
}

// MARK: - Deep Link Service

class DeepLinkService: DeepLinkServiceProtocol {
    
    let deepLinkReceived = PassthroughSubject<DeepLinkData, Never>()
    
    private let navigationManager: NavigationManager
    private var cancellables = Set<AnyCancellable>()
    
    init(navigationManager: NavigationManager) {
        self.navigationManager = navigationManager
        setupSubscriptions()
    }
    
    private func setupSubscriptions() {
        deepLinkReceived
            .receive(on: DispatchQueue.main)
            .sink { [weak self] deepLinkData in
                self?.processDeepLinkData(deepLinkData)
            }
            .store(in: &cancellables)
    }
    
    // MARK: - Deep Link Handling
    
    func handleDeepLink(url: URL) -> Bool {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true),
              let host = components.host else {
            return false
        }
        
        var pathComponents = components.path.components(separatedBy: "/").filter { !$0.isEmpty }
        
        // Parse query parameters
        var queryParams: [String: String] = [:]
        if let queryItems = components.queryItems {
            queryParams = queryItems.reduce(into: [:]) { result, item in
                if let value = item.value {
                    result[item.name] = value
                }
            }
        }
        
        // Handle different deep link types
        switch host {
        case "room":
            if let roomId = pathComponents.first {
                let deepLinkData = DeepLinkData(
                    type: .room,
                    roomId: roomId,
                    callId: nil,
                    userId: nil,
                    action: .navigateToRoom(roomId: roomId),
                    queryParams: queryParams
                )
                deepLinkReceived.send(deepLinkData)
                return true
            }
        
        case "call":
            if let callId = pathComponents.first {
                let deepLinkData = DeepLinkData(
                    type: .call,
                    roomId: nil,
                    callId: callId,
                    userId: nil,
                    action: .navigateToCall(callId: callId),
                    queryParams: queryParams
                )
                deepLinkReceived.send(deepLinkData)
                return true
            }
        
        case "user", "profile":
            if let userId = pathComponents.first {
                let deepLinkData = DeepLinkData(
                    type: .user,
                    roomId: nil,
                    callId: nil,
                    userId: userId,
                    action: .navigateToUserProfile(userId: userId),
                    queryParams: queryParams
                )
                deepLinkReceived.send(deepLinkData)
                return true
            }
        
        case "settings":
            let deepLinkData = DeepLinkData(
                type: .settings,
                roomId: nil,
                callId: nil,
                userId: nil,
                action: .navigateToSettings,
                queryParams: queryParams
            )
            deepLinkReceived.send(deepLinkData)
            return true
        
        case "login", "auth":
            let deepLinkData = DeepLinkData(
                type: .auth,
                roomId: nil,
                callId: nil,
                userId: nil,
                action: .navigateToLogin,
                queryParams: queryParams
            )
            deepLinkReceived.send(deepLinkData)
            return true
        
        case "invite":
            if let roomId = queryParams["room_id"] ?? pathComponents.first {
                let deepLinkData = DeepLinkData(
                    type: .invite,
                    roomId: roomId,
                    callId: nil,
                    userId: nil,
                    action: .navigateToRoomInvite(roomId: roomId),
                    queryParams: queryParams
                )
                deepLinkReceived.send(deepLinkData)
                return true
            }
        
        default:
            // Handle unknown deep links
            let deepLinkData = DeepLinkData(
                type: .unknown,
                roomId: nil,
                callId: nil,
                userId: nil,
                action: .showError(message: "Unknown deep link"),
                queryParams: queryParams
            )
            deepLinkReceived.send(deepLinkData)
            return false
        }
        
        return false
    }
    
    func handleUniversalLink(url: URL) -> Bool {
        // Universal links typically have the app's domain
        // Parse and handle similar to deep links
        return handleDeepLink(url: url)
    }
    
    // MARK: - Deep Link Processing
    
    func processDeepLinkData(_ data: DeepLinkData) {
        switch data.action {
        case .navigateToRoom(let roomId):
            navigationManager.navigateToRoom(roomId)
        case .navigateToCall(let callId):
            navigationManager.navigateToCall(callId: callId)
        case .navigateToUserProfile(let userId):
            navigationManager.navigateToUserProfile(userId)
        case .navigateToSettings:
            navigationManager.navigateToSettings()
        case .navigateToLogin:
            navigationManager.switchToNotLoggedInFlow()
        case .navigateToRoomInvite(let roomId):
            navigationManager.navigateToRoomInvite(roomId: roomId)
        case .showError(let message):
            showError(message: message)
        }
    }
    
    private func showError(message: String) {
        // Show error to user
    }
}

// MARK: - Deep Link Models

enum DeepLinkType {
    case room
    case call
    case user
    case settings
    case auth
    case invite
    case unknown
}

enum DeepLinkAction {
    case navigateToRoom(roomId: String)
    case navigateToCall(callId: String)
    case navigateToUserProfile(userId: String)
    case navigateToSettings
    case navigateToLogin
    case navigateToRoomInvite(roomId: String)
    case showError(message: String)
}

struct DeepLinkData {
    let type: DeepLinkType
    let roomId: String?
    let callId: String?
    let userId: String?
    let action: DeepLinkAction
    let queryParams: [String: String]
}

// MARK: - App Delegate Integration

class AppDelegateDeepLinkHandler {
    
    private let deepLinkService: DeepLinkServiceProtocol
    
    init(deepLinkService: DeepLinkServiceProtocol) {
        self.deepLinkService = deepLinkService
    }
    
    // For AppDelegate
    func handleDeepLink(url: URL) -> Bool {
        return deepLinkService.handleDeepLink(url: url)
    }
    
    // For SceneDelegate
    func handleUniversalLink(url: URL) -> Bool {
        return deepLinkService.handleUniversalLink(url: url)
    }
    
    // For handling user activity (universal links)
    func handleUserActivity(_ userActivity: NSUserActivity) -> Bool {
        if userActivity.activityType == NSUserActivityTypeBrowsingWeb,
           let url = userActivity.webpageURL {
            return handleUniversalLink(url: url)
        }
        return false
    }
}
