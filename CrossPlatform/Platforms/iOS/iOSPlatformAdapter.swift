//
//  iOSPlatformAdapter.swift
//  NetInfinity iOS Platform Adapter
//
//

import Foundation
import UIKit
import UserNotifications

// MARK: - iOS Platform Adapter

/// iOS platform-specific adapter
public class iOSPlatformAdapter: PlatformAdapterProtocol {
    
    public init() {
        // Initialize iOS-specific components
    }
    
    // MARK: - Platform Information
    
    public var platformName: String {
        return "iOS"
    }
    
    public var platformVersion: String {
        return UIDevice.current.systemVersion
    }
    
    public var deviceModel: String {
        return UIDevice.current.model
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
        // iOS-specific notification implementation
        let center = UNUserNotificationCenter.current()
        
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = message
        content.sound = .default
        
        let trigger = UNTimeIntervalNotificationTrigger(timeInterval: 1, repeats: false)
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: trigger)
        
        center.add(request) { error in
            if let error = error {
                print("Error showing iOS notification: \(error)")
            }
        }
    }
    
    public func scheduleNotification(title: String, message: String, delay: TimeInterval) {
        // iOS-specific scheduled notification
        let center = UNUserNotificationCenter.current()
        
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = message
        content.sound = .default
        
        let trigger = UNTimeIntervalNotificationTrigger(timeInterval: delay, repeats: false)
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: trigger)
        
        center.add(request) { error in
            if let error = error {
                print("Error scheduling iOS notification: \(error)")
            }
        }
    }
    
    // MARK: - System Integration
    
    public func openURL(_ url: URL) {
        // iOS-specific URL opening
        UIApplication.shared.open(url, options: [:], completionHandler: nil)
    }
    
    public func openFile(_ url: URL) {
        // iOS-specific file opening
        UIApplication.shared.open(url, options: [:], completionHandler: nil)
    }
    
    public func shareContent(_ content: [Any], completion: ((Bool) -> Void)?) {
        // iOS-specific sharing
        let activityViewController = UIActivityViewController(activityItems: content, applicationActivities: nil)
        
        // Get the current view controller
        if let rootViewController = UIApplication.shared.windows.first?.rootViewController {
            rootViewController.present(activityViewController, animated: true, completion: nil)
            completion?(true)
        } else {
            completion?(false)
        }
    }
    
    // MARK: - App Lifecycle
    
    public func registerForAppLifecycleEvents() {
        // iOS-specific app lifecycle registration
        let notificationCenter = NotificationCenter.default
        
        notificationCenter.addObserver(
            forName: UIApplication.willTerminateNotification,
            object: nil,
            queue: .main
        ) { _ in
            self.handleAppWillTerminate()
        }
    }
    
    public func handleAppWillTerminate() {
        // iOS-specific app termination handling
        print("Handling iOS app termination")
    }
    
    // MARK: - Window Management
    
    public func createWindow(title: String, size: CGSize) -> WindowReference {
        // iOS-specific window creation (returns main window)
        print("Creating iOS window: \(title) - \(size)")
        return iOSWindowReference()
    }
    
    public func showWindow(_ window: WindowReference) {
        // iOS-specific window showing
        print("Showing iOS window")
    }
    
    public func hideWindow(_ window: WindowReference) {
        // iOS-specific window hiding
        print("Hiding iOS window")
    }
    
    public func closeWindow(_ window: WindowReference) {
        // iOS-specific window closing
        print("Closing iOS window")
    }
    
    // MARK: - System Dialogs
    
    public func showAlert(title: String, message: String, completion: (() -> Void)?) {
        // iOS-specific alert dialog
        let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default) { _ in
            completion?()
        })
        
        if let rootViewController = UIApplication.shared.windows.first?.rootViewController {
            rootViewController.present(alert, animated: true, completion: nil)
        }
    }
    
    public func showConfirm(title: String, message: String, completion: ((Bool) -> Void)?) {
        // iOS-specific confirmation dialog
        let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default) { _ in
            completion?(true)
        })
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in
            completion?(false)
        })
        
        if let rootViewController = UIApplication.shared.windows.first?.rootViewController {
            rootViewController.present(alert, animated: true, completion: nil)
        }
    }
    
    public func showFilePicker(allowMultiple: Bool, completion: (([URL]?) -> Void)?) {
        // iOS-specific file picker
        let documentPicker = UIDocumentPickerViewController(
            documentTypes: ["public.data"],
            in: .import
        )
        documentPicker.allowsMultipleSelection = allowMultiple
        
        if let rootViewController = UIApplication.shared.windows.first?.rootViewController {
            rootViewController.present(documentPicker, animated: true, completion: nil)
        }
    }
    
    // MARK: - Platform-Specific Features
    
    public func registerForIOSSpecificFeatures() {
        // Register iOS-specific features
        print("Registered for iOS-specific features")
    }
    
    public func setupIOSShortcuts() {
        // Setup iOS shortcuts
        print("Setting up iOS shortcuts")
    }
    
    public func configureIOSSpotlight() {
        // Configure iOS Spotlight search
        print("Configuring iOS Spotlight search")
    }
    
    public func setupIOSWidgets() {
        // Setup iOS widgets
        print("Setting up iOS widgets")
    }
    
    public func configureIOSAppClips() {
        // Configure iOS App Clips
        print("Configuring iOS App Clips")
    }
}

// MARK: - iOS Window Reference

public class iOSWindowReference: WindowReference {
    public var isVisible: Bool = true
    public var title: String = ""
    public var size: CGSize = UIScreen.main.bounds.size
    
    public func show() {
        isVisible = true
        print("iOS window shown")
    }
    
    public func hide() {
        isVisible = false
        print("iOS window hidden")
    }
    
    public func close() {
        print("iOS window closed")
    }
    
    public func setTitle(_ title: String) {
        self.title = title
        print("iOS window title set to: \(title)")
    }
    
    public func setSize(_ size: CGSize) {
        self.size = size
        print("iOS window size set to: \(size)")
    }
}

// MARK: - iOS Notification Service

public class iOSNotificationService: NSObject, NotificationServiceProtocol, UNUserNotificationCenterDelegate {
    
    public let notificationReceived = PassthroughSubject<NotificationData, Never>()
    
    public override init() {
        super.init()
        setupNotificationCenter()
    }
    
    private func setupNotificationCenter() {
        let center = UNUserNotificationCenter.current()
        center.delegate = self
    }
    
    public func requestPermission() async -> Bool {
        do {
            let settings = await UNUserNotificationCenter.current().notificationSettings()
            
            if settings.authorizationStatus == .authorized {
                return true
            }
            
            let granted = try await UNUserNotificationCenter.current().requestAuthorization(
                options: [.alert, .badge, .sound]
            )
            return granted
        } catch {
            print("Error requesting iOS notification permission: \(error)")
            return false
        }
    }
    
    public func registerForRemoteNotifications() async {
        let success = await requestPermission()
        if success {
            DispatchQueue.main.async {
                UIApplication.shared.registerForRemoteNotifications()
            }
        }
    }
    
    public func handleRemoteNotification(userInfo: [AnyHashable: Any]) {
        // Handle iOS remote notification
        print("Handling iOS remote notification: \(userInfo)")
        let notificationData = parseNotificationData(userInfo: userInfo)
        notificationReceived.send(notificationData)
        
        // Show notification if app is in foreground
        if UIApplication.shared.applicationState == .active {
            showNotification(for: notificationData)
        }
    }
    
    public func scheduleLocalNotification(title: String, body: String, userInfo: [AnyHashable: Any]?) {
        // Schedule iOS local notification
        print("Scheduling iOS local notification: \(title) - \(body)")
        
        let center = UNUserNotificationCenter.current()
        
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        
        if let userInfo = userInfo {
            content.userInfo = userInfo
        }
        
        let trigger = UNTimeIntervalNotificationTrigger(timeInterval: 1, repeats: false)
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: trigger)
        
        center.add(request) { error in
            if let error = error {
                print("Error scheduling iOS notification: \(error)")
            }
        }
    }
    
    public func clearAllNotifications() {
        // Clear all iOS notifications
        print("Clearing all iOS notifications")
        let center = UNUserNotificationCenter.current()
        center.removeAllPendingNotificationRequests()
        center.removeAllDeliveredNotifications()
    }
    
    public func processNotificationResponse(userInfo: [AnyHashable: Any]) -> NotificationAction? {
        // Process iOS notification response
        print("Processing iOS notification response: \(userInfo)")
        let notificationData = parseNotificationData(userInfo: userInfo)
        return notificationData.action
    }
    
    private func showNotification(for data: NotificationData) {
        let center = UNUserNotificationCenter.current()
        
        let content = UNMutableNotificationContent()
        
        switch data.type {
        case .message:
            content.title = "New Message"
            content.body = "You have a new message"
        case .invite:
            content.title = "New Invite"
            content.body = "You have a new room invite"
        case .reaction:
            content.title = "New Reaction"
            content.body = "Someone reacted to your message"
        case .mention:
            content.title = "New Mention"
            content.body = "You were mentioned in a conversation"
        case .call:
            content.title = "Incoming Call"
            content.body = "You have an incoming call"
        case .system:
            content.title = "System Notification"
            content.body = "System notification received"
        case .unknown:
            content.title = "Notification"
            content.body = "New notification received"
        }
        
        content.sound = .default
        
        let trigger = UNTimeIntervalNotificationTrigger(timeInterval: 1, repeats: false)
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: trigger)
        
        center.add(request) { error in
            if let error = error {
                print("Error showing iOS notification: \(error)")
            }
        }
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
    
    // MARK: - UNUserNotificationCenterDelegate
    
    public func userNotificationCenter(_ center: UNUserNotificationCenter, 
                                     willPresent notification: UNNotification,
                                     withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        
        // Handle notification when app is in foreground
        let userInfo = notification.request.content.userInfo
        handleRemoteNotification(userInfo: userInfo)
        
        // Show notification as banner
        completionHandler([.banner, .sound, .badge])
    }
    
    public func userNotificationCenter(_ center: UNUserNotificationCenter,
                                     didReceive response: UNNotificationResponse,
                                     withCompletionHandler completionHandler: @escaping () -> Void) {
        
        // Handle notification tap
        let userInfo = response.notification.request.content.userInfo
        let action = processNotificationResponse(userInfo: userInfo)
        
        // Notify about the action
        if let action = action {
            notificationReceived.send(NotificationData(
                type: .system,
                roomId: nil,
                callId: nil,
                messageId: nil,
                action: action
            ))
        }
        
        completionHandler()
    }
}

// MARK: - iOS Deep Link Handler

public class iOSDeepLinkHandler: DeepLinkServiceProtocol {
    
    public let deepLinkReceived = PassthroughSubject<DeepLinkData, Never>()
    
    private let navigationManager: NavigationManager
    
    public init(navigationManager: NavigationManager) {
        self.navigationManager = navigationManager
    }
    
    public func handleDeepLink(url: URL) -> Bool {
        // Handle iOS deep link
        print("Handling iOS deep link: \(url.absoluteString)")
        
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
        // Handle iOS universal link
        print("Handling iOS universal link: \(url.absoluteString)")
        return handleDeepLink(url: url)
    }
    
    public func processDeepLinkData(_ data: DeepLinkData) {
        // Process deep link data
        print("Processing iOS deep link data: \(data)")
        
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
            print("iOS deep link error: \(message)")
        }
    }
}