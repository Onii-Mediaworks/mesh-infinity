//
//  NotificationService.swift
//  NetInfinity
//
//

import Foundation
import UserNotifications
import Combine
#if canImport(UIKit)
import UIKit
#endif
#if canImport(AppKit)
import AppKit
#endif

// MARK: - Notification Service Protocol

protocol NotificationServiceProtocol {
    var notificationReceived: PassthroughSubject<NotificationData, Never> { get }
    
    func requestPermission() async -> Bool
    func registerForRemoteNotifications() async
    func handleRemoteNotification(userInfo: [AnyHashable: Any])
    func scheduleLocalNotification(title: String, body: String, userInfo: [AnyHashable: Any]?)
    func clearAllNotifications()
    func processNotificationResponse(userInfo: [AnyHashable: Any]) -> NotificationAction?
}

// MARK: - Notification Service

class NotificationService: NSObject, NotificationServiceProtocol, UNUserNotificationCenterDelegate {
    
    let notificationReceived = PassthroughSubject<NotificationData, Never>()
    
    private let notificationCenter = UNUserNotificationCenter.current()
    private var cancellables = Set<AnyCancellable>()
    
    override init() {
        super.init()
        notificationCenter.delegate = self
    }
    
    // MARK: - Permission Management
    
    func requestPermission() async -> Bool {
        do {
            let settings = await notificationCenter.notificationSettings()
            
            if settings.authorizationStatus == .authorized {
                return true
            }
            
            let granted = try await notificationCenter.requestAuthorization(options: [.alert, .badge, .sound])
            return granted
        } catch {
            print("Error requesting notification permission: \(error)")
            return false
        }
    }
    
    // MARK: - Remote Notifications
    
    func registerForRemoteNotifications() async {
        let success = await requestPermission()
        if success {
            DispatchQueue.main.async {
                #if canImport(UIKit)
                UIApplication.shared.registerForRemoteNotifications()
                #elseif canImport(AppKit)
                NSApplication.shared.registerForRemoteNotifications()
                #endif
            }
        }
    }
    
    func handleRemoteNotification(userInfo: [AnyHashable: Any]) {
        let notificationData = parseNotificationData(userInfo: userInfo)
        notificationReceived.send(notificationData)
        
        // Handle notification when app is in foreground
        #if canImport(UIKit)
        if UIApplication.shared.applicationState == .active {
            // Show in-app notification or update UI
        }
        #elseif canImport(AppKit)
        if NSApplication.shared.isActive {
            // Show in-app notification or update UI
        }
        #endif
    }
    
    // MARK: - Local Notifications
    
    func scheduleLocalNotification(title: String, body: String, userInfo: [AnyHashable: Any]? = nil) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        
        if let userInfo = userInfo {
            content.userInfo = userInfo
        }
        
        let trigger = UNTimeIntervalNotificationTrigger(timeInterval: 1, repeats: false)
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: trigger)
        
        notificationCenter.add(request) { error in
            if let error = error {
                print("Error scheduling local notification: \(error)")
            }
        }
    }
    
    func clearAllNotifications() {
        notificationCenter.removeAllPendingNotificationRequests()
        notificationCenter.removeAllDeliveredNotifications()
    }
    
    // MARK: - Notification Processing
    
    func processNotificationResponse(userInfo: [AnyHashable: Any]) -> NotificationAction? {
        let notificationData = parseNotificationData(userInfo: userInfo)
        
        switch notificationData.type {
        case .message:
            return .navigateToRoom(roomId: notificationData.roomId)
        case .invite:
            return .navigateToRoom(roomId: notificationData.roomId)
        case .reaction:
            return .navigateToRoom(roomId: notificationData.roomId)
        case .mention:
            return .navigateToRoom(roomId: notificationData.roomId)
        case .call:
            return .navigateToCall(callId: notificationData.callId)
        case .system:
            return .navigateToSettings
        case .unknown:
            return nil
        }
    }
    
    // MARK: - UNUserNotificationCenterDelegate
    
    func userNotificationCenter(_ center: UNUserNotificationCenter, 
                              willPresent notification: UNNotification,
                              withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        
        // Handle notification when app is in foreground
        let userInfo = notification.request.content.userInfo
        handleRemoteNotification(userInfo: userInfo)
        
        // Show notification as banner
        completionHandler([.banner, .sound, .badge])
    }
    
    func userNotificationCenter(_ center: UNUserNotificationCenter,
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
    
    // MARK: - Private Methods
    
    private func parseNotificationData(userInfo: [AnyHashable: Any]) -> NotificationData {
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

// MARK: - Notification Models

enum NotificationType {
    case message
    case invite
    case reaction
    case mention
    case call
    case system
    case unknown
}

enum NotificationAction {
    case navigateToRoom(roomId: String?)
    case navigateToCall(callId: String?)
    case navigateToSettings
    case showAlert(title: String, message: String)
}

struct NotificationData {
    let type: NotificationType
    let roomId: String?
    let callId: String?
    let messageId: String?
    let action: NotificationAction?
}

// MARK: - Push Notification Handler

class PushNotificationHandler {
    
    private let notificationService: NotificationServiceProtocol
    private let navigationManager: NavigationManager
    
    init(notificationService: NotificationServiceProtocol, navigationManager: NavigationManager) {
        self.notificationService = notificationService
        self.navigationManager = navigationManager
        
        setupSubscriptions()
    }
    
    private func setupSubscriptions() {
        notificationService.notificationReceived
            .receive(on: DispatchQueue.main)
            .sink { [weak self] notificationData in
                self?.handleNotification(notificationData)
            }
            .store(in: &cancellables)
    }
    
    private func handleNotification(_ data: NotificationData) {
        switch data.action {
        case .navigateToRoom(let roomId):
            if let roomId = roomId {
                navigationManager.navigateToRoom(roomId)
            }
        case .navigateToCall(let callId):
            if let callId = callId {
                navigationManager.navigateToCall(callId: callId)
            }
        case .navigateToSettings:
            navigationManager.navigateToSettings()
        case .showAlert(let title, let message):
            showAlert(title: title, message: message)
        case .none:
            break
        }
    }
    
    private func showAlert(title: String, message: String) {
        // Show alert to user
    }
    
    private var cancellables = Set<AnyCancellable>()
}
