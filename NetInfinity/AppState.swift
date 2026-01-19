//
//  AppState.swift
//  NetInfinity
//
//

import SwiftUI
import Combine

// MARK: - App State Management

final class AppState: ObservableObject {
    @Published var authenticationState: AuthenticationState = .unknown
    @Published var currentIdentity: LocalIdentity?
    @Published var colorScheme: ColorScheme = .light
    @Published var isLoading = false
    @Published var error: AppError?
    
    private var cancellables = Set<AnyCancellable>()
    
    init() {
        setupObservers()
    }
    
    private func setupObservers() {
        // Observe authentication state changes
        $authenticationState
            .sink { state in
                print("Authentication state changed to: \(state)")
                // Additional side effects can be added here
            }
            .store(in: &cancellables)
    }
    
    func setReady(with identity: LocalIdentity) {
        currentIdentity = identity
        MessageContext.currentUserId = identity.id
        authenticationState = .ready(identity: identity)
    }
    
    func clearIdentity() {
        currentIdentity = nil
        MessageContext.currentUserId = nil
        authenticationState = .unknown
    }
    
    func setLoading(_ isLoading: Bool) {
        self.isLoading = isLoading
    }
    
    func setError(_ error: AppError?) {
        self.error = error
    }
    
    func clearError() {
        error = nil
    }
}

// MARK: - Authentication State

extension AppState {
    enum AuthenticationState {
        case unknown
        case ready(identity: LocalIdentity)
    }
}

// MARK: - Error Handling

enum AppError: Error, Identifiable {
    case authenticationFailed
    case networkError(Error)
    case invalidSession
    case unknownError
    
    var id: String {
        switch self {
        case .authenticationFailed: return "authenticationFailed"
        case .networkError: return "networkError"
        case .invalidSession: return "invalidSession"
        case .unknownError: return "unknownError"
        }
    }
    
    var title: String {
        switch self {
        case .authenticationFailed: return "Authentication Failed"
        case .networkError: return "Network Error"
        case .invalidSession: return "Invalid Session"
        case .unknownError: return "Error"
        }
    }
    
    var message: String {
        switch self {
        case .authenticationFailed: return "Failed to authenticate. Please try again."
        case .networkError(let error): return "Network error: \(error.localizedDescription)"
        case .invalidSession: return "Your session has expired. Please log in again."
        case .unknownError: return "An unknown error occurred. Please try again."
        }
    }
}
