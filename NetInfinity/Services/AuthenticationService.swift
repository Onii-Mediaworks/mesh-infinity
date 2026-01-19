//
//  AuthenticationService.swift
//  NetInfinity
//
//

import Foundation
import Combine
#if canImport(UIKit)
import UIKit
#endif

// MARK: - Authentication Service Protocol

protocol AuthenticationService {
    /// Current authentication state
    var authenticationState: AnyPublisher<AuthenticationState, Never> { get }
    
    /// Current session if authenticated
    var currentSession: AnyPublisher<Session?, Never> { get }
    
    /// Login with email and password
    func login(email: String, password: String) async throws -> Session
    
    /// Login with SSO
    func loginWithSSO(provider: String, token: String) async throws -> Session
    
    /// Register new account
    func register(email: String, password: String, displayName: String) async throws -> Session
    
    /// Restore existing session
    func restoreSession() async throws -> Session?
    
    /// Logout current session
    func logout() async throws
    
    /// Check if session is valid
    func checkSessionValidity() async -> Bool
    
    /// Handle OAuth callback
    func handleOAuthCallback(url: URL) async throws -> Session
}

// MARK: - Authentication State

enum AuthenticationState: Equatable {
    case unknown
    case authenticated(session: Session)
    case notAuthenticated
    case onboardingRequired
    case sessionExpired
    
    var isAuthenticated: Bool {
        if case .authenticated = self {
            return true
        }
        return false
    }
}

// MARK: - Session Model

struct Session: Codable, Equatable, Identifiable {
    let id: String
    let userId: String
    let accessToken: String
    let refreshToken: String?
    let homeserver: String
    let deviceId: String
    let createdAt: Date
    let expiresAt: Date
    
    var isValid: Bool {
        return Date() < expiresAt
    }
    
    var expiresSoon: Bool {
        let soonThreshold = Date().addingTimeInterval(300) // 5 minutes
        return Date() < expiresAt && expiresAt < soonThreshold
    }
}

// MARK: - Authentication Error

enum AuthenticationError: Error, LocalizedError {
    case invalidCredentials
    case networkError(Error)
    case sessionExpired
    case invalidResponse
    case accountLocked
    case registrationFailed
    case unknownError
    case cancelled
    
    var errorDescription: String? {
        switch self {
        case .invalidCredentials:
            return "Invalid email or password"
        case .networkError(let error):
            return "Network error: \(error.localizedDescription)"
        case .sessionExpired:
            return "Session expired. Please log in again."
        case .invalidResponse:
            return "Invalid server response"
        case .accountLocked:
            return "Account locked. Please contact support."
        case .registrationFailed:
            return "Registration failed. Please try again."
        case .unknownError:
            return "An unknown error occurred"
        case .cancelled:
            return "Operation cancelled"
        }
    }
}

// MARK: - Default Authentication Service Implementation

final class DefaultAuthenticationService: AuthenticationService {
    private let networkService: NetworkService
    private let storageService: StorageService
    private let sessionState = CurrentValueSubject<AuthenticationState, Never>(.unknown)
    private let currentSessionSubject = CurrentValueSubject<Session?, Never>(nil)
    
    init(networkService: NetworkService, storageService: StorageService) {
        self.networkService = networkService
        self.storageService = storageService
        Task { await restoreSessionIfNeeded() }
    }
    
    var authenticationState: AnyPublisher<AuthenticationState, Never> {
        sessionState.eraseToAnyPublisher()
    }
    
    var currentSession: AnyPublisher<Session?, Never> {
        currentSessionSubject.eraseToAnyPublisher()
    }
    
    // MARK: - Public Methods
    
    func login(email: String, password: String) async throws -> Session {
        // Validate input
        guard !email.isEmpty, !password.isEmpty else {
            throw AuthenticationError.invalidCredentials
        }
        
        // Call login API
        let request = LoginRequest(email: email, password: password)
        let session: Session = try await networkService.post("/login", body: request)
        
        // Store session
        try await storeSession(session)
        
        return session
    }
    
    func loginWithSSO(provider: String, token: String) async throws -> Session {
        // Call SSO login API
        let request = SSOLoginRequest(provider: provider, token: token)
        let session: Session = try await networkService.post("/sso_login", body: request)
        
        // Store session
        try await storeSession(session)
        
        return session
    }
    
    func register(email: String, password: String, displayName: String) async throws -> Session {
        // Validate input
        guard !email.isEmpty, !password.isEmpty, !displayName.isEmpty else {
            throw AuthenticationError.invalidCredentials
        }
        
        // Call registration API
        let request = RegistrationRequest(
            email: email,
            password: password,
            displayName: displayName
        )
        let session: Session = try await networkService.post("/register", body: request)
        
        // Store session
        try await storeSession(session)
        
        return session
    }
    
    func restoreSession() async throws -> Session? {
        // Try to restore from storage
        if let storedSession: Session = try await storageService.get("current_session") {
            // Check if session is still valid
            if await checkSessionValidity() {
                return storedSession
            } else {
                // Session expired, clear it
                try await logout()
                return nil
            }
        }
        return nil
    }
    
    func logout() async throws {
        // Clear current session
        currentSessionSubject.send(nil)
        sessionState.send(.notAuthenticated)
        
        // Call logout API if there's a valid session
        if let currentSession = currentSessionSubject.value {
            let request = LogoutRequest(sessionId: currentSession.id)
            try await networkService.postVoid("/logout", body: request)
        }
        
        // Clear stored session
        try storageService.remove("current_session")
    }
    
    func checkSessionValidity() async -> Bool {
        guard let currentSession = currentSessionSubject.value else {
            return false
        }
        
        if currentSession.isValid {
            return true
        }
        
        // Try to refresh token if expired but refresh token exists
        if let refreshToken = currentSession.refreshToken {
            do {
                let refreshRequest = RefreshTokenRequest(
                    sessionId: currentSession.id,
                    refreshToken: refreshToken
                )
                let newSession: Session = try await networkService.post("/refresh_token", body: refreshRequest)
                try await storeSession(newSession)
                return true
            } catch {
                return false
            }
        }
        
        return false
    }
    
    func handleOAuthCallback(url: URL) async throws -> Session {
        // Parse OAuth callback URL and extract token
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true),
              let queryItems = components.queryItems,
              let token = queryItems.first(where: { $0.name == "token" })?.value else {
            throw AuthenticationError.invalidResponse
        }
        
        // Exchange token for session
        let request = OAuthCallbackRequest(token: token)
        let session: Session = try await networkService.post("/oauth_callback", body: request)
        
        // Store session
        try await storeSession(session)
        
        return session
    }
    
    // MARK: - Private Methods
    
    private func storeSession(_ session: Session) async throws {
        // Store in secure storage
        try await storageService.set("current_session", value: session)
        
        // Update subjects
        currentSessionSubject.send(session)
        sessionState.send(.authenticated(session: session))
    }
    
    private func restoreSessionIfNeeded() async {
        do {
            if let session = try await restoreSession() {
                currentSessionSubject.send(session)
                sessionState.send(.authenticated(session: session))
            } else {
                sessionState.send(.notAuthenticated)
            }
        } catch {
            sessionState.send(.notAuthenticated)
        }
    }
}

// MARK: - Request Models

private enum DeviceIdProvider {
    static var current: String {
        #if canImport(UIKit)
        return UIDevice.current.identifierForVendor?.uuidString ?? "unknown"
        #else
        return UUID().uuidString
        #endif
    }
}

private struct LoginRequest: Codable {
    let email: String
    let password: String
    let deviceId: String = DeviceIdProvider.current
}

private struct SSOLoginRequest: Codable {
    let provider: String
    let token: String
    let deviceId: String = DeviceIdProvider.current
}

private struct RegistrationRequest: Codable {
    let email: String
    let password: String
    let displayName: String
    let deviceId: String = DeviceIdProvider.current
}

private struct LogoutRequest: Codable {
    let sessionId: String
}

private struct RefreshTokenRequest: Codable {
    let sessionId: String
    let refreshToken: String
}

private struct OAuthCallbackRequest: Codable {
    let token: String
    let deviceId: String = DeviceIdProvider.current
}
