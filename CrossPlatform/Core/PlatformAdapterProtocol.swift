//
//  PlatformAdapterProtocol.swift
//  NetInfinity Cross-Platform Core
//
//

import Foundation
import Combine

// MARK: - Platform Adapter Protocol

/// Protocol for platform-specific adapters
public protocol PlatformAdapterProtocol {
    
    // MARK: - Platform Information
    
    var platformName: String { get }
    var platformVersion: String { get }
    var deviceModel: String { get }
    
    // MARK: - File System
    
    func getDocumentsDirectory() -> URL
    func getCacheDirectory() -> URL
    func getAppSupportDirectory() -> URL
    
    // MARK: - Notifications
    
    func showNotification(title: String, message: String)
    func scheduleNotification(title: String, message: String, delay: TimeInterval)
    
    // MARK: - System Integration
    
    func openURL(_ url: URL)
    func openFile(_ url: URL)
    func shareContent(_ content: [Any], completion: ((Bool) -> Void)?)
    
    // MARK: - App Lifecycle
    
    func registerForAppLifecycleEvents()
    func handleAppWillTerminate()
    
    // MARK: - Window Management
    
    func createWindow(title: String, size: CGSize) -> WindowReference
    func showWindow(_ window: WindowReference)
    func hideWindow(_ window: WindowReference)
    func closeWindow(_ window: WindowReference)
    
    // MARK: - System Dialogs
    
    func showAlert(title: String, message: String, completion: (() -> Void)?)
    func showConfirm(title: String, message: String, completion: ((Bool) -> Void)?)
    func showFilePicker(allowMultiple: Bool, completion: (([URL]?) -> Void)?)
}

// MARK: - Window Reference Protocol

public protocol WindowReference: AnyObject {
    var isVisible: Bool { get set }
    var title: String { get set }
    var size: CGSize { get set }
    
    func show()
    func hide()
    func close()
    func setTitle(_ title: String)
    func setSize(_ size: CGSize)
}

// MARK: - Platform Adapter Factory

public struct PlatformAdapterFactory {
    
    public static func createAdapter() -> PlatformAdapterProtocol {
        let platform = PlatformDetector.currentPlatform
        
        switch platform {
        case .windows:
            return WindowsPlatformAdapter()
        case .linux:
            return LinuxPlatformAdapter()
        case .macOS:
            return macOSPlatformAdapter()
        case .iOS:
            return iOSPlatformAdapter()
        case .android:
            return AndroidPlatformAdapter()
        case .unknown:
            return GenericPlatformAdapter()
        }
    }
    
    public static func createNotificationService() -> NotificationServiceProtocol {
        let platform = PlatformDetector.currentPlatform
        
        switch platform {
        case .windows:
            return WindowsNotificationService()
        case .linux:
            return LinuxNotificationService()
        case .macOS:
            return macOSNotificationService()
        case .iOS:
            return iOSNotificationService()
        case .android:
            return AndroidNotificationService()
        case .unknown:
            return GenericNotificationService()
        }
    }
    
    public static func createDeepLinkHandler(navigationManager: NavigationManager) -> DeepLinkServiceProtocol {
        let platform = PlatformDetector.currentPlatform
        
        switch platform {
        case .windows:
            return WindowsDeepLinkHandler(navigationManager: navigationManager)
        case .linux:
            return LinuxDeepLinkHandler(navigationManager: navigationManager)
        case .macOS:
            return macOSDeepLinkHandler(navigationManager: navigationManager)
        case .iOS:
            return iOSDeepLinkHandler(navigationManager: navigationManager)
        case .android:
            return AndroidDeepLinkHandler(navigationManager: navigationManager)
        case .unknown:
            return GenericDeepLinkHandler(navigationManager: navigationManager)
        }
    }
}

// MARK: - Generic Platform Adapter (Fallback)

public class GenericPlatformAdapter: PlatformAdapterProtocol {
    
    public init() {
        // Initialize generic platform adapter
    }
    
    public var platformName: String {
        return "Unknown Platform"
    }
    
    public var platformVersion: String {
        return ProcessInfo.processInfo.operatingSystemVersionString
    }
    
    public var deviceModel: String {
        return "Unknown Device"
    }
    
    public func getDocumentsDirectory() -> URL {
        return FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first ?? 
            FileManager.default.temporaryDirectory
    }
    
    public func getCacheDirectory() -> URL {
        return FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first ?? 
            FileManager.default.temporaryDirectory
    }
    
    public func getAppSupportDirectory() -> URL {
        return FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first ?? 
            FileManager.default.temporaryDirectory
    }
    
    public func showNotification(title: String, message: String) {
        print("Generic Notification: \(title) - \(message)")
    }
    
    public func scheduleNotification(title: String, message: String, delay: TimeInterval) {
        print("Scheduled Generic Notification: \(title) - \(message) in \(delay) seconds")
    }
    
    public func openURL(_ url: URL) {
        print("Opening URL on generic platform: \(url.absoluteString)")
    }
    
    public func openFile(_ url: URL) {
        print("Opening file on generic platform: \(url.path)")
    }
    
    public func shareContent(_ content: [Any], completion: ((Bool) -> Void)?) {
        print("Sharing content on generic platform: \(content)")
        completion?(true)
    }
    
    public func registerForAppLifecycleEvents() {
        print("Registered for generic app lifecycle events")
    }
    
    public func handleAppWillTerminate() {
        print("Handling generic app termination")
    }
    
    public func createWindow(title: String, size: CGSize) -> WindowReference {
        print("Creating generic window: \(title) - \(size)")
        return GenericWindowReference()
    }
    
    public func showWindow(_ window: WindowReference) {
        print("Showing generic window")
    }
    
    public func hideWindow(_ window: WindowReference) {
        print("Hiding generic window")
    }
    
    public func closeWindow(_ window: WindowReference) {
        print("Closing generic window")
    }
    
    public func showAlert(title: String, message: String, completion: (() -> Void)?) {
        print("Showing generic alert: \(title) - \(message)")
        completion?()
    }
    
    public func showConfirm(title: String, message: String, completion: ((Bool) -> Void)?) {
        print("Showing generic confirm: \(title) - \(message)")
        completion?(true)
    }
    
    public func showFilePicker(allowMultiple: Bool, completion: (([URL]?) -> Void)?) {
        print("Showing generic file picker")
        completion?([])
    }
}

// MARK: - Generic Window Reference

public class GenericWindowReference: WindowReference {
    public var isVisible: Bool = false
    public var title: String = ""
    public var size: CGSize = .zero
    
    public func show() {
        isVisible = true
        print("Generic window shown")
    }
    
    public func hide() {
        isVisible = false
        print("Generic window hidden")
    }
    
    public func close() {
        print("Generic window closed")
    }
    
    public func setTitle(_ title: String) {
        self.title = title
        print("Generic window title set to: \(title)")
    }
    
    public func setSize(_ size: CGSize) {
        self.size = size
        print("Generic window size set to: \(size)")
    }
}

// MARK: - Generic Notification Service

public class GenericNotificationService: NotificationServiceProtocol {
    
    public let notificationReceived = PassthroughSubject<NotificationData, Never>()
    
    public init() {
        // Initialize generic notification service
    }
    
    public func requestPermission() async -> Bool {
        print("Requesting generic notification permission")
        return true
    }
    
    public func registerForRemoteNotifications() async {
        print("Registering for generic remote notifications")
    }
    
    public func handleRemoteNotification(userInfo: [AnyHashable: Any]) {
        print("Handling generic remote notification: \(userInfo)")
        let notificationData = parseNotificationData(userInfo: userInfo)
        notificationReceived.send(notificationData)
    }
    
    public func scheduleLocalNotification(title: String, body: String, userInfo: [AnyHashable: Any]?) {
        print("Scheduling generic local notification: \(title) - \(body)")
    }
    
    public func clearAllNotifications() {
        print("Clearing all generic notifications")
    }
    
    public func processNotificationResponse(userInfo: [AnyHashable: Any]) -> NotificationAction? {
        print("Processing generic notification response: \(userInfo)")
        return nil
    }
    
    private func parseNotificationData(userInfo: [AnyHashable: Any]) -> NotificationData {
        return NotificationData(
            type: .system,
            roomId: nil,
            callId: nil,
            messageId: nil,
            action: nil
        )
    }
}

// MARK: - Generic Deep Link Handler

public class GenericDeepLinkHandler: DeepLinkServiceProtocol {
    
    public let deepLinkReceived = PassthroughSubject<DeepLinkData, Never>()
    
    private let navigationManager: NavigationManager
    
    public init(navigationManager: NavigationManager) {
        self.navigationManager = navigationManager
    }
    
    public func handleDeepLink(url: URL) -> Bool {
        print("Handling generic deep link: \(url.absoluteString)")
        
        let deepLinkData = DeepLinkData(
            type: .unknown,
            roomId: nil,
            callId: nil,
            userId: nil,
            action: .showError(message: "Deep link not supported on this platform"),
            queryParams: [:]
        )
        
        deepLinkReceived.send(deepLinkData)
        processDeepLinkData(deepLinkData)
        
        return false
    }
    
    public func handleUniversalLink(url: URL) -> Bool {
        print("Handling generic universal link: \(url.absoluteString)")
        return handleDeepLink(url: url)
    }
    
    public func processDeepLinkData(_ data: DeepLinkData) {
        print("Processing generic deep link data: \(data)")
        
        switch data.action {
        case .navigateToRoom(let roomId):
            navigationManager.navigateToRoom(roomId ?? "")
        case .navigateToCall(let callId):
            navigationManager.navigateToCall(callId: callId ?? "")
        case .navigateToUserProfile(let userId):
            navigationManager.navigateToUserProfile(userId ?? "")
        case .navigateToSettings:
            navigationManager.navigateToSettings()
        case .navigateToLogin:
            navigationManager.switchToNotLoggedInFlow()
        case .navigateToRoomInvite(let roomId):
            navigationManager.navigateToRoomInvite(roomId: roomId ?? "")
        case .showError(let message):
            print("Generic deep link error: \(message)")
        }
    }
}