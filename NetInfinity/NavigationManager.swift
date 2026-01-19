//
//  NavigationManager.swift
//  NetInfinity
//
//

import SwiftUI
import Combine

// MARK: - Navigation Destination

/// Navigation destinations based on Android RootFlowNode architecture
enum NavigationDestination: Hashable, Identifiable {
    case splashScreen
    case home
    case room(roomId: String)
    case roomDetails(roomId: String)
    case userProfile(userId: String)
    case settings
    case mediaViewer(mediaId: String)
    case search
    case createRoom
    case notifications
    case call(callId: String)
    case roomInvite(roomId: String)
     
    // Authentication flows
    case onboarding
    case createAccount
    case forgotPassword
    
    // Account management
    case accountSelect(currentSessionId: String, intent: Intent?, permalinkData: PermalinkData?)
    case signedOutFlow(sessionId: String)
    
    // Utility
    case bugReport
    
    // Deep linking
    case deepLink(url: URL)

    var id: String {
        switch self {
        case .splashScreen:
            return "splashScreen"
        case .home:
            return "home"
        case .room(let roomId):
            return "room:\(roomId)"
        case .roomDetails(let roomId):
            return "roomDetails:\(roomId)"
        case .userProfile(let userId):
            return "userProfile:\(userId)"
        case .settings:
            return "settings"
        case .mediaViewer(let mediaId):
            return "mediaViewer:\(mediaId)"
        case .search:
            return "search"
        case .createRoom:
            return "createRoom"
        case .notifications:
            return "notifications"
        case .call(let callId):
            return "call:\(callId)"
        case .roomInvite(let roomId):
            return "roomInvite:\(roomId)"
        case .onboarding:
            return "onboarding"
        case .createAccount:
            return "createAccount"
        case .forgotPassword:
            return "forgotPassword"
        case .accountSelect(let currentSessionId, let intent, let permalinkData):
            return "accountSelect:\(currentSessionId):\(String(describing: intent)):\(String(describing: permalinkData))"
        case .signedOutFlow(let sessionId):
            return "signedOutFlow:\(sessionId)"
        case .bugReport:
            return "bugReport"
        case .deepLink(let url):
            return "deepLink:\(url.absoluteString)"
        }
    }
}

// MARK: - Intent and Permalink Data Types

/// Intent representation for cross-platform compatibility
struct Intent: Hashable {
    let url: URL?
    let payload: [String: String]?
    
    init(url: URL? = nil, payload: [String: String]? = nil) {
        self.url = url
        self.payload = payload
    }
}

/// Permalink data types based on Android implementation
enum PermalinkData: Hashable {
    case room(roomId: String, eventId: String?, threadId: String?)
    case user(userId: String)
    case fallbackLink
    case roomEmailInviteLink
}

// MARK: - Navigation Manager

final class NavigationManager: ObservableObject {
    @Published var path = NavigationPath()
    @Published var presentedSheet: NavigationDestination?
    @Published var fullScreenCover: NavigationDestination?
    @Published var selectedTab: Tab = .chats
    @Published var selectedRoomId: String?
    
    private var cancellables = Set<AnyCancellable>()
    
    init() {
        setupObservers()
    }
    
    private func setupObservers() {
        // Observe navigation changes for analytics
        $path
            .sink { path in
                print("Navigation path changed: \(path.count) destinations")
                // Track navigation events
            }
            .store(in: &cancellables)
    }
    
    // MARK: - Navigation Methods
    
    func navigate(to destination: NavigationDestination) {
        path.append(destination)
    }
    
    func navigateBack() {
        guard !path.isEmpty else { return }
        path.removeLast()
    }
    
    func navigateToRoot() {
        path = NavigationPath()
    }
    
    func presentSheet(_ destination: NavigationDestination) {
        presentedSheet = destination
    }
    
    func dismissSheet() {
        presentedSheet = nil
    }
    
    func presentFullScreenCover(_ destination: NavigationDestination) {
        fullScreenCover = destination
    }
    
    func dismissFullScreenCover() {
        fullScreenCover = nil
    }
    
    // MARK: - Convenience Methods
    
    func navigateToRoom(_ roomId: String) {
        selectedTab = .chats
        #if os(macOS)
        selectedRoomId = roomId
        #else
        navigate(to: .room(roomId: roomId))
        #endif
    }
    
    func navigateToUserProfile(_ userId: String) {
        selectedTab = .chats
        navigate(to: .userProfile(userId: userId))
    }
    
    func navigateToSettings() {
        selectedTab = .settings
        navigateToRoot()
    }
    
    func navigateToMediaViewer(_ mediaId: String) {
        navigate(to: .mediaViewer(mediaId: mediaId))
    }
    
    func navigateToCall(callId: String) {
        navigate(to: .call(callId: callId))
    }
    
    func navigateToRoomInvite(roomId: String) {
        navigate(to: .roomInvite(roomId: roomId))
    }
    
    // MARK: - Deep Link Handling
    
    func handleDeepLink(_ url: URL) {
        // Parse and handle deep links
        navigate(to: .deepLink(url: url))
    }
    
    // MARK: - RootFlowNode Methods (Android Adaptation)
    
    /// Switch to logged in flow - equivalent to Android's switchToLoggedInFlow
    func switchToLoggedInFlow(sessionId: String, navId: Int) {
        navigateToRoot()
        selectedTab = .chats
    }
    
    /// Switch to not logged in flow - equivalent to Android's switchToNotLoggedInFlow
    func switchToNotLoggedInFlow(params: LoginParams? = nil) {
        navigateToHome()
    }
    
    /// Switch to signed out flow - equivalent to Android's switchToSignedOutFlow
    func switchToSignedOutFlow(sessionId: String) {
        navigateToRoot()
        navigate(to: .signedOutFlow(sessionId: sessionId))
    }
    
    /// Navigate to account select - equivalent to Android's AccountSelect navigation
    func navigateToAccountSelect(currentSessionId: String, intent: Intent? = nil, permalinkData: PermalinkData? = nil) {
        navigate(to: .accountSelect(currentSessionId: currentSessionId, intent: intent, permalinkData: permalinkData))
    }
    
    // MARK: - Intent Handling (Android Adaptation)
    
    /// Handle intent - equivalent to Android's handleIntent
    func handleIntent(_ intent: Intent) {
        // This would be called from AppDelegate or SceneDelegate
        // For now, just handle deep links
        if let url = intent.url {
            handleDeepLink(url)
        }
    }
    
    /// Navigate based on permalink data - equivalent to Android's navigateTo(permalinkData:)
    func navigateTo(permalinkData: PermalinkData) {
        switch permalinkData {
        case .room(let roomId, _, _):
            navigateToRoom(roomId)
            // TODO: Scroll to event if provided
        case .user(let userId):
            navigateToUserProfile(userId)
        case .fallbackLink, .roomEmailInviteLink:
            // Handle fallback cases
            break
        }
    }
    
    /// Navigate based on deep link data - equivalent to Android's navigateTo(deeplinkData:)
    func navigateTo(deeplinkData: DeeplinkData) {
        // This would be implemented based on your deep link structure
        // For now, just handle basic room navigation
    }
    
    // MARK: - Authentication Flow
    
    func navigateToLogin() {
        navigateToHome()
    }
    
    func navigateToOnboarding() {
        navigateToRoot()
        navigate(to: .onboarding)
    }
    
    func navigateToHome() {
        navigateToRoot()
        selectedTab = .chats
    }
    
    // MARK: - Utility Navigation
    
    func navigateToBugReport() {
        presentSheet(.bugReport)
    }
    
    func dismissBugReport() {
        dismissSheet()
    }

}

// MARK: - Supporting Types

/// Login parameters - equivalent to Android's LoginParams
struct LoginParams: Hashable {
    let accountProvider: String?
    let loginHint: String?
    
    init(accountProvider: String? = nil, loginHint: String? = nil) {
        self.accountProvider = accountProvider
        self.loginHint = loginHint
    }
}

/// Deep link data - equivalent to Android's DeeplinkData
enum DeeplinkData: Hashable {
    case root(sessionId: String)
    case room(sessionId: String, roomId: String, eventId: String?, threadId: String?)
}

// MARK: - Navigation Extensions

extension NavigationDestination {
    var title: String {
        switch self {
        case .splashScreen: return "Splash"
        case .home: return "Home"
        case .room: return "Room"
        case .roomDetails: return "Room Details"
        case .userProfile: return "Profile"
        case .settings: return "Settings"
        case .mediaViewer: return "Media"
        case .search: return "Search"
        case .createRoom: return "Create Room"
        case .notifications: return "Notifications"
        case .call: return "Call"
        case .roomInvite: return "Room Invite"
        case .onboarding: return "Onboarding"
        case .createAccount: return "Create Account"
        case .forgotPassword: return "Forgot Password"
        case .accountSelect: return "Select Account"
        case .signedOutFlow: return "Signed Out"
        case .bugReport: return "Bug Report"
        case .deepLink: return "Deep Link"
        }
    }
    
    var iconName: String? {
        switch self {
        case .splashScreen: return "hourglass"
        case .home: return "house"
        case .room: return "bubble.left"
        case .roomDetails: return "info.circle"
        case .userProfile: return "person"
        case .settings: return "gear"
        case .mediaViewer: return "photo"
        case .search: return "magnifyingglass"
        case .createRoom: return "plus.bubble"
        case .notifications: return "bell"
        case .call: return "phone"
        case .roomInvite: return "envelope"
        case .onboarding: return "hand.wave"
        case .createAccount: return "person.badge.plus"
        case .forgotPassword: return "questionmark"
        case .accountSelect: return "person.2"
        case .signedOutFlow: return "arrow.left.square"
        case .bugReport: return "ladybug"
        case .deepLink: return "link"
        }
    }
}

// MARK: - Navigation View Modifiers

struct NavigationDestinationViewModifier: ViewModifier {
    @EnvironmentObject var navigationManager: NavigationManager
    let destination: NavigationDestination
    let content: () -> AnyView
    
    func body(content: Content) -> some View {
        content
            .navigationDestination(for: NavigationDestination.self) { destination in
                AnyView(NavigationDestinationHost(destination: destination))
            }
    }
}

// MARK: - Destination Host

struct NavigationDestinationHost: View {
    let destination: NavigationDestination
    
    @EnvironmentObject var dependencyContainer: AppDependencyContainer
    
    var body: some View {
        switch destination {
        case .splashScreen:
            SplashScreenView()
        case .home:
            HomeView(roomService: dependencyContainer.roomService)
        case .room(let roomId):
            RoomView(roomId: roomId, roomService: dependencyContainer.roomService)
        case .roomDetails(let roomId):
            RoomDetailsView(roomId: roomId, roomService: dependencyContainer.roomService)
        case .userProfile(let userId):
            UserProfileView(userId: userId)
        case .settings:
            SettingsView()
        case .mediaViewer(let mediaId):
            MediaViewerScreen(mediaId: mediaId)
        case .search:
            SearchView(roomService: dependencyContainer.roomService)
        case .createRoom:
            CreateRoomView(roomService: dependencyContainer.roomService)
        case .notifications:
            NotificationsView()
        case .call(let callId):
            CallView(callId: callId)
        case .roomInvite(let roomId):
            RoomInviteView(roomId: roomId)
        case .onboarding:
            OnboardingView()
        case .createAccount:
            CreateAccountView(authenticationService: dependencyContainer.authenticationService)
        case .forgotPassword:
            ForgotPasswordView()
        case .accountSelect(let currentSessionId, let intent, let permalinkData):
            AccountSelectView(currentSessionId: currentSessionId, intent: intent, permalinkData: permalinkData)
        case .signedOutFlow(let sessionId):
            SignedOutView(sessionId: sessionId)
        case .bugReport:
            BugReportView()
        case .deepLink(let url):
            DeepLinkHandlerView(url: url)
        }
    }
}

// MARK: - Sheet and Cover Modifiers

private struct SheetNavigationModifier: ViewModifier {
    @EnvironmentObject var navigationManager: NavigationManager
    
    func body(content: Content) -> some View {
        content
            .sheet(item: $navigationManager.presentedSheet) { destination in
                NavigationStack {
                    NavigationDestinationHost(destination: destination)
                }
            }
    }
}

private struct FullScreenCoverNavigationModifier: ViewModifier {
    @EnvironmentObject var navigationManager: NavigationManager
    
    func body(content: Content) -> some View {
        #if os(macOS)
        content
            .sheet(item: $navigationManager.fullScreenCover) { destination in
                NavigationStack {
                    NavigationDestinationHost(destination: destination)
                }
            }
        #else
        content
            .fullScreenCover(item: $navigationManager.fullScreenCover) { destination in
                NavigationStack {
                    NavigationDestinationHost(destination: destination)
                }
            }
        #endif
    }
}

// MARK: - View Extensions

extension View {
    func withNavigation() -> some View {
        modifier(NavigationDestinationViewModifier(destination: .home) {
            AnyView(HomeView(roomService: AppDependencyContainer().roomService))
        })
    }
    
    func withSheetNavigation() -> some View {
        modifier(SheetNavigationModifier())
    }
    
    func withFullScreenCoverNavigation() -> some View {
        modifier(FullScreenCoverNavigationModifier())
    }
}
