//
//  RootView.swift
//  NetInfinity
//
//

import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

// MARK: - Root View

struct RootView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var navigationManager: NavigationManager
    @EnvironmentObject var dependencyContainer: AppDependencyContainer
    @AppStorage("settings.nodeMode") private var nodeModeRaw = NodeMode.client.rawValue
    
    var body: some View {
        Group {
            switch appState.authenticationState {
            case .unknown:
                SplashScreenView()
                    .onAppear {
                        setupIdentity()
                    }
            case .ready:
                if nodeMode.includesClient {
                    MainTabView()
                        .environmentObject(navigationManager)
                } else {
                    ServerModeView()
                }
            }
        }
        .withSheetNavigation()
        .withFullScreenCoverNavigation()
        .overlay {
            if appState.isLoading {
                LoadingOverlay()
            }
        }
        .overlay {
            if let error = appState.error {
                ErrorView(error: error)
                    .transition(.opacity)
            }
        }
        .onAppear {
            setupAppearance()
        }
    }

    private var nodeMode: NodeMode {
        NodeMode(rawValue: nodeModeRaw) ?? .client
    }
    
    // MARK: - Identity Setup
    
    private func setupIdentity() {
        Task {
            await loadIdentity()
        }
    }
    
    private func loadIdentity() async {
        do {
            appState.setLoading(true)
            let identity = try await dependencyContainer.identityService.loadOrCreateIdentity()
            appState.setReady(with: identity)
        } catch {
            appState.setError(AppError.unknownError)
        }
        
        appState.setLoading(false)
    }
    
    // MARK: - Appearance Setup
    
    private func setupAppearance() {
#if canImport(UIKit)
        // Configure navigation bar appearance
        let appearance = UINavigationBarAppearance()
        appearance.configureWithOpaqueBackground()
        appearance.backgroundColor = UIColor.systemBackground
        appearance.titleTextAttributes = [
            .foregroundColor: UIColor.label,
            .font: UIFont.systemFont(ofSize: 18, weight: .semibold)
        ]
        
        UINavigationBar.appearance().standardAppearance = appearance
        UINavigationBar.appearance().scrollEdgeAppearance = appearance
        UINavigationBar.appearance().compactAppearance = appearance
        
        // Configure tab bar appearance
        let tabBarAppearance = UITabBarAppearance()
        tabBarAppearance.configureWithOpaqueBackground()
        tabBarAppearance.backgroundColor = UIColor.systemBackground
        
        UITabBar.appearance().standardAppearance = tabBarAppearance
        UITabBar.appearance().scrollEdgeAppearance = tabBarAppearance
#endif
    }
}

// MARK: - Server Mode

struct ServerModeView: View {
    @EnvironmentObject var appState: AppState
    
    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text("Server mode is active. This node runs headless services for storage, routing, and local presence. The server process is managed separately from the client UI.")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                
                Section("Identity") {
                    statusRow(title: "Identity", value: identityStatus)
                    statusRow(title: "Node ID", value: identityPreview)
                }
                
                Section("Settings") {
                    NavigationLink {
                        SettingsView()
                    } label: {
                        Label("Networking & Node Mode", systemImage: "gear")
                    }
                }
            }
            .navigationTitle("Server Mode")
        }
    }
    
    private var identityStatus: String {
        appState.currentIdentity == nil ? "Pending" : "Ready"
    }
    
    private var identityPreview: String {
        guard let id = appState.currentIdentity?.id else {
            return "Generating..."
        }
        return String(id.prefix(16)) + "..."
    }
    
    private func statusRow(title: String, value: String) -> some View {
        HStack {
            Text(title)
            Spacer()
            Text(value)
                .foregroundColor(.secondary)
        }
    }
}

// MARK: - Splash Screen

struct SplashScreenView: View {
    var body: some View {
        ZStack {
            Color("Background")
                .edgesIgnoringSafeArea(.all)
            
            VStack(spacing: 24) {
                Image("AppLogo")
                    .resizable()
                    .aspectRatio(contentMode: .fit)
                    .frame(width: 120, height: 120)
                    .accessibilityIdentifier("splashLogo")
                
                ProgressView()
                    .progressViewStyle(CircularProgressViewStyle(tint: .accentColor))
                    .scaleEffect(1.5)
                    .accessibilityIdentifier("splashProgress")
                
                Text("NetInfinity")
                    .font(.largeTitle)
                    .fontWeight(.bold)
                    .foregroundColor(.primary)
                    .accessibilityIdentifier("splashTitle")
            }
        }
    }
}

// MARK: - Main Tab View

struct MainTabView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var navigationManager: NavigationManager
    @EnvironmentObject var dependencyContainer: AppDependencyContainer
    
    var body: some View {
        NavigationStack(path: $navigationManager.path) {
            TabView(selection: $navigationManager.selectedTab) {
                HomeView(roomService: dependencyContainer.roomService)
                    .tabItem {
                        Label("Chats", systemImage: "bubble.left.and.bubble.right")
                    }
                    .tag(Tab.chats)
                
                SearchView(roomService: dependencyContainer.roomService)
                    .tabItem {
                        Label("Search", systemImage: "magnifyingglass")
                    }
                    .tag(Tab.search)
                
                NotificationsView()
                    .tabItem {
                        Label("Alerts", systemImage: "bell")
                    }
                    .tag(Tab.notifications)
                
                SettingsView()
                    .tabItem {
                        Label("Settings", systemImage: "gear")
                    }
                    .tag(Tab.settings)
            }
            .navigationDestination(for: NavigationDestination.self) { destination in
                NavigationDestinationHost(destination: destination)
            }
        }
    }
}

// MARK: - Tab Enum

enum Tab: Hashable {
    case chats
    case search
    case notifications
    case settings
}

// MARK: - Loading Overlay

struct LoadingOverlay: View {
    var body: some View {
        ZStack {
            Color.black.opacity(0.3)
                .edgesIgnoringSafeArea(.all)
                .transition(.opacity)
            
            VStack(spacing: 16) {
                ProgressView()
                    .progressViewStyle(CircularProgressViewStyle(tint: .white))
                    .scaleEffect(1.5)
                
                Text("Loading...")
                    .foregroundColor(.white)
                    .font(.headline)
            }
            .padding(24)
            .background(Color.black.opacity(0.7))
            .cornerRadius(12)
        }
    }
}

// MARK: - Error View

struct ErrorView: View {
    let error: AppError
    @EnvironmentObject var appState: AppState
    
    var body: some View {
        VStack {
            Spacer()
            
            VStack(spacing: 16) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 48))
                    .foregroundColor(.white)
                
                Text(error.title)
                    .font(.headline)
                    .foregroundColor(.white)
                    .multilineTextAlignment(.center)
                
                Text(error.message)
                    .font(.subheadline)
                    .foregroundColor(.white.opacity(0.9))
                    .multilineTextAlignment(.center)
                
                Button("OK") {
                    appState.clearError()
                }
                .buttonStyle(.borderedProminent)
                .tint(.white)
                .foregroundColor(.black)
            }
            .padding(24)
            .background(Color.red)
            .cornerRadius(12)
            .padding(.horizontal, 24)
            
            Spacer()
        }
        .transition(.move(edge: .bottom))
        .animation(.spring(), value: error.id)
    }
}

// MARK: - Preview

struct RootView_Previews: PreviewProvider {
    static var previews: some View {
        RootView()
            .environmentObject(AppState())
            .environmentObject(NavigationManager())
            .environmentObject(AppDependencyContainer())
    }
}
