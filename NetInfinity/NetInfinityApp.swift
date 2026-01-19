//
//  NetInfinityApp.swift
//  NetInfinity
//
//

import SwiftUI

@main
struct NetInfinityApp: App {
    @StateObject private var appState = AppState()
    @StateObject private var dependencyContainer = AppDependencyContainer()
    @StateObject private var navigationManager = NavigationManager()
    
    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(appState)
                .environmentObject(dependencyContainer)
                .environmentObject(navigationManager)
                .preferredColorScheme(appState.colorScheme)
        }
    }
}
