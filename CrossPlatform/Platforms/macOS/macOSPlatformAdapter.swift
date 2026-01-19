//
//  macOSPlatformAdapter.swift
//  NetInfinity macOS Platform Adapter
//
//

import Foundation
import AppKit

// MARK: - macOS Platform Adapter

/// macOS platform-specific adapter
public class macOSPlatformAdapter: PlatformAdapterProtocol {
    
    public init() {
        // Initialize macOS-specific components
    }
    
    // MARK: - Platform Information
    
    public var platformName: String {
        return "macOS"
    }
    
    public var platformVersion: String {
        return ProcessInfo.processInfo.operatingSystemVersionString
    }
    
    public var deviceModel: String {
        var size = 0
        sysctlbyname("hw.model", nil, &size, nil, 0)
        var machine = [CChar](repeating: 0, count: size)
        sysctlbyname("hw.model", &machine, &size, nil, 0)
        return String(cString: machine)
    }
    
    // MARK: - File System
    
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
    
    // MARK: - Notifications
    
    public func showNotification(title: String, message: String) {
        // macOS-specific notification implementation
        let notification = NSUserNotification()
        notification.title = title
        notification.informativeText = message
        notification.soundName = NSUserNotificationDefaultSoundName
        
        NSUserNotificationCenter.default.deliver(notification)
    }
    
    public func scheduleNotification(title: String, message: String, delay: TimeInterval) {
        // macOS-specific scheduled notification
        let notification = NSUserNotification()
        notification.title = title
        notification.informativeText = message
        notification.deliveryDate = Date().addingTimeInterval(delay)
        notification.soundName = NSUserNotificationDefaultSoundName
        
        NSUserNotificationCenter.default.scheduleNotification(notification)
    }
    
    // MARK: - System Integration
    
    public func openURL(_ url: URL) {
        // macOS-specific URL opening
        NSWorkspace.shared.open(url)
    }
    
    public func openFile(_ url: URL) {
        // macOS-specific file opening
        NSWorkspace.shared.open(url)
    }
    
    public func shareContent(_ content: [Any], completion: ((Bool) -> Void)?) {
        // macOS-specific sharing
        let sharingService = NSSharingService(named: .composeEmail)
        sharingService?.subject = "Shared from NetInfinity"
        sharingService?.perform(withItems: content)
        completion?(true)
    }
    
    // MARK: - App Lifecycle
    
    public func registerForAppLifecycleEvents() {
        // macOS-specific app lifecycle registration
        let notificationCenter = NotificationCenter.default
        notificationCenter.addObserver(
            forName: NSApplication.willTerminateNotification,
            object: nil,
            queue: .main
        ) { _ in
            self.handleAppWillTerminate()
        }
    }
    
    public func handleAppWillTerminate() {
        // macOS-specific app termination handling
        print("Handling macOS app termination")
    }
    
    // MARK: - Window Management
    
    public func createWindow(title: String, size: CGSize) -> WindowReference {
        // macOS-specific window creation
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: size.width, height: size.height),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = title
        window.center()
        
        return macOSWindowReference(window: window)
    }
    
    public func showWindow(_ window: WindowReference) {
        // macOS-specific window showing
        if let macOSWindow = window as? macOSWindowReference {
            macOSWindow.window.makeKeyAndOrderFront(nil)
        }
    }
    
    public func hideWindow(_ window: WindowReference) {
        // macOS-specific window hiding
        if let macOSWindow = window as? macOSWindowReference {
            macOSWindow.window.orderOut(nil)
        }
    }
    
    public func closeWindow(_ window: WindowReference) {
        // macOS-specific window closing
        if let macOSWindow = window as? macOSWindowReference {
            macOSWindow.window.close()
        }
    }
    
    // MARK: - System Dialogs
    
    public func showAlert(title: String, message: String, completion: (() -> Void)?) {
        // macOS-specific alert dialog
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.alertStyle = .informational
        alert.addButton(withTitle: "OK")
        
        alert.runModal()
        completion?()
    }
    
    public func showConfirm(title: String, message: String, completion: ((Bool) -> Void)?) {
        // macOS-specific confirmation dialog
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.alertStyle = .warning
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")
        
        let response = alert.runModal()
        completion?(response == .alertFirstButtonReturn)
    }
    
    public func showFilePicker(allowMultiple: Bool, completion: (([URL]?) -> Void)?) {
        // macOS-specific file picker
        let openPanel = NSOpenPanel()
        openPanel.title = "Select Files"
        openPanel.allowsMultipleSelection = allowMultiple
        openPanel.canChooseDirectories = false
        openPanel.canChooseFiles = true
        
        openPanel.begin { response in
            if response == .OK {
                completion?(openPanel.urls)
            } else {
                completion?(nil)
            }
        }
    }
    
    // MARK: - Platform-Specific Features
    
    public func registerForMacOSSpecificFeatures() {
        // Register macOS-specific features
        print("Registered for macOS-specific features")
    }
    
    public func setupMacOSMenuBar() {
        // Setup macOS menu bar
        print("Setting up macOS menu bar")
    }
    
    public func configureMacOSDock() {
        // Configure macOS dock
        print("Configuring macOS dock")
    }
    
    public func setupMacOSTouchBar() {
        // Setup macOS touch bar
        print("Setting up macOS touch bar")
    }
}

// MARK: - macOS Window Reference

public class macOSWindowReference: WindowReference {
    public let window: NSWindow
    
    public init(window: NSWindow) {
        self.window = window
    }
    
    public var isVisible: Bool {
        return window.isVisible
    }
    
    public var title: String {
        get { return window.title }
        set { window.title = newValue }
    }
    
    public var size: CGSize {
        get { return window.frame.size }
        set { window.setContentSize(newValue) }
    }
    
    public func show() {
        window.makeKeyAndOrderFront(nil)
    }
    
    public func hide() {
        window.orderOut(nil)
    }
    
    public func close() {
        window.close()
    }
    
    public func setTitle(_ title: String) {
        window.title = title
    }
    
    public func setSize(_ size: CGSize) {
        window.setContentSize(size)
    }
    
    public func center() {
        window.center()
    }
    
    public func makeKey() {
        window.makeKeyAndOrderFront(nil)
    }
}

// MARK: - macOS Notification Service

public class macOSNotificationService: NotificationServiceProtocol {
    
    public let notificationReceived = PassthroughSubject<NotificationData, Never>()
    
    public init() {
        // Initialize macOS notification service
        setupNotificationCenter()
    }
    
    private func setupNotificationCenter() {
        let center = NSUserNotificationCenter.default
        center.delegate = self
    }
    
    public func requestPermission() async -> Bool {
        // macOS notification permission request
        print("Requesting macOS notification permission")
        return true
    }
    
    public func registerForRemoteNotifications() async {
        // macOS remote notification registration
        print("Registering for macOS remote notifications")
    }
    
    public func handleRemoteNotification(userInfo: [AnyHashable: Any]) {
        // Handle macOS remote notification
        print("Handling macOS remote notification: \(userInfo)")
        let notificationData = parseNotificationData(userInfo: userInfo)
        notificationReceived.send(notificationData)
        
        // Show notification
        showNotification(for: notificationData)
    }
    
    public func scheduleLocalNotification(title: String, body: String, userInfo: [AnyHashable: Any]?) {
        // Schedule macOS local notification
        print("Scheduling macOS local notification: \(title) - \(body)")
        
        let notification = NSUserNotification()
        notification.title = title
        notification.informativeText = body
        notification.deliveryDate = Date().addingTimeInterval(1)
        notification.soundName = NSUserNotificationDefaultSoundName
        
        if let userInfo = userInfo {
            notification.userInfo = userInfo
        }
        
        NSUserNotificationCenter.default.scheduleNotification(notification)
    }
    
    public func clearAllNotifications() {
        // Clear all macOS notifications
        print("Clearing all macOS notifications")
        NSUserNotificationCenter.default.removeAllDeliveredNotifications()
    }
    
    public func processNotificationResponse(userInfo: [AnyHashable: Any]) -> NotificationAction? {
        // Process macOS notification response
        print("Processing macOS notification response: \(userInfo)")
        let notificationData = parseNotificationData(userInfo: userInfo)
        return notificationData.action
    }
    
    private func showNotification(for data: NotificationData) {
        let notification = NSUserNotification()
        
        switch data.type {
        case .message:
            notification.title = "New Message"
            notification.informativeText = "You have a new message"
        case .invite:
            notification.title = "New Invite"
            notification.informativeText = "You have a new room invite"
        case .reaction:
            notification.title = "New Reaction"
            notification.informativeText = "Someone reacted to your message"
        case .mention:
            notification.title = "New Mention"
            notification.informativeText = "You were mentioned in a conversation"
        case .call:
            notification.title = "Incoming Call"
            notification.informativeText = "You have an incoming call"
        case .system:
            notification.title = "System Notification"
            notification.informativeText = "System notification received"
        case .unknown:
            notification.title = "Notification"
            notification.informativeText = "New notification received"
        }
        
        notification.soundName = NSUserNotificationDefaultSoundName
        NSUserNotificationCenter.default.deliver(notification)
    }
    
    private func parseNotificationData(userInfo: [AnyHashable: Any]) -> NotificationData {
        // Parse notification data
        let typeString = userInfo["type"] as? String ?? "unknown"
        let type: NotificationType
        
        switch typeString.lowercased() {
        case "message": type = .message
        case "invite": type = .invite
        case "reaction": type = .reaction
        case "mention": type = .mention
        case "call": type = .call
        case "system": type = .system
        default: type = .unknown
        }
        
        let roomId = userInfo["room_id"] as? String
        let callId = userInfo["call_id"] as? String
        let messageId = userInfo["message_id"] as? String
        
        return NotificationData(
            type: type,
            roomId: roomId,
            callId: callId,
            messageId: messageId,
            action: nil
        )
    }
}

extension macOSNotificationService: NSUserNotificationCenterDelegate {
    public func userNotificationCenter(_ center: NSUserNotificationCenter, 
                                     didActivate notification: NSUserNotification) {
        // Handle notification activation
        if let userInfo = notification.userInfo {
            let action = processNotificationResponse(userInfo: userInfo)
            if let action = action {
                notificationReceived.send(NotificationData(
                    type: .system,
                    roomId: nil,
                    callId: nil,
                    messageId: nil,
                    action: action
                ))
            }
        }
    }
    
    public func userNotificationCenter(_ center: NSUserNotificationCenter,
                                     shouldPresent notification: NSUserNotification) -> Bool {
        return true
    }
}

// MARK: - macOS Deep Link Handler

public class macOSDeepLinkHandler: DeepLinkServiceProtocol {
    
    public let deepLinkReceived = PassthroughSubject<DeepLinkData, Never>()
    
    private let navigationManager: NavigationManager
    
    public init(navigationManager: NavigationManager) {
        self.navigationManager = navigationManager
    }
    
    public func handleDeepLink(url: URL) -> Bool {
        // Handle macOS deep link
        print("Handling macOS deep link: \(url.absoluteString)")
        
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
                processDeepLinkData(deepLinkData)
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
                processDeepLinkData(deepLinkData)
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
                processDeepLinkData(deepLinkData)
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
            processDeepLinkData(deepLinkData)
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
            processDeepLinkData(deepLinkData)
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
                processDeepLinkData(deepLinkData)
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
    }
    
    public func handleUniversalLink(url: URL) -> Bool {
        // Handle macOS universal link
        print("Handling macOS universal link: \(url.absoluteString)")
        return handleDeepLink(url: url)
    }
    
    public func processDeepLinkData(_ data: DeepLinkData) {
        // Process deep link data
        print("Processing macOS deep link data: \(data)")
        
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
            print("macOS deep link error: \(message)")
        }
    }
}