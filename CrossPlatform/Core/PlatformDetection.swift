//
//  PlatformDetection.swift
//  NetInfinity Cross-Platform Core
//
//

import Foundation

// MARK: - Platform Detection

/// Comprehensive platform detection for cross-platform support
public enum Platform {
    case windows
    case linux
    case macOS
    case iOS
    case android
    case unknown(String)
    
    public var isDesktop: Bool {
        switch self {
        case .windows, .linux, .macOS: return true
        case .iOS, .android: return false
        case .unknown: return false
        }
    }
    
    public var isMobile: Bool {
        switch self {
        case .iOS, .android: return true
        case .windows, .linux, .macOS: return false
        case .unknown: return false
        }
    }
    
    public var name: String {
        switch self {
        case .windows: return "Windows"
        case .linux: return "Linux"
        case .macOS: return "macOS"
        case .iOS: return "iOS"
        case .android: return "Android"
        case .unknown(let name): return name
        }
    }
}

// MARK: - Device Form Factor

public enum DeviceFormFactor {
    case phone
    case tablet
    case desktop
    case tv
    case car
    case watch
    case unknown
    
    public var isMobile: Bool {
        switch self {
        case .phone, .tablet, .watch: return true
        case .desktop, .tv, .car: return false
        case .unknown: return false
        }
    }
    
    public var isDesktop: Bool {
        switch self {
        case .desktop: return true
        case .phone, .tablet, .tv, .car, .watch: return false
        case .unknown: return false
        }
    }
}

// MARK: - Platform Detector

public struct PlatformDetector {
    
    public static var currentPlatform: Platform {
        #if os(Windows)
        return .windows
        #elseif os(Linux)
        return .linux
        #elseif os(macOS)
        return .macOS
        #elseif os(iOS)
        return .iOS
        #elseif os(Android)
        return .android
        #else
        return .unknown(ProcessInfo.processInfo.operatingSystemVersionString)
        #endif
    }
    
    public static var currentDeviceFormFactor: DeviceFormFactor {
        #if os(iOS) || os(Android)
        if UIDevice.current.userInterfaceIdiom == .phone {
            return .phone
        } else if UIDevice.current.userInterfaceIdiom == .pad {
            return .tablet
        } else if UIDevice.current.userInterfaceIdiom == .tv {
            return .tv
        } else if UIDevice.current.userInterfaceIdiom == .carPlay {
            return .car
        }
        #elseif os(watchOS)
        return .watch
        #else
        // Desktop platforms
        return .desktop
        #endif
    }
    
    public static var isMobilePlatform: Bool {
        return currentPlatform.isMobile
    }
    
    public static var isDesktopPlatform: Bool {
        return currentPlatform.isDesktop
    }
    
    public static var isTouchInterface: Bool {
        #if os(iOS) || os(Android)
        return true
        #else
        // Check if running on a touch-enabled desktop
        return false
        #endif
    }
    
    public static var supportsWindowManagement: Bool {
        return !currentPlatform.isMobile
    }
    
    public static var supportsBackgroundProcessing: Bool {
        switch currentPlatform {
        case .windows, .linux, .macOS: return true
        case .iOS, .android: return false
        case .unknown: return false
        }
    }
}

// MARK: - Platform Capabilities

public struct PlatformCapabilities {
    
    public static func supportsFeature(_ feature: PlatformFeature) -> Bool {
        switch feature {
        case .notifications:
            return true // All platforms support some form of notifications
        case .backgroundSync:
            return PlatformDetector.currentPlatform.isDesktop
        case .fileSystemAccess:
            return PlatformDetector.currentPlatform.isDesktop
        case .cameraAccess:
            return true // Mobile and desktop support camera
        case .microphoneAccess:
            return true // Mobile and desktop support microphone
        case .locationServices:
            return true // Mobile and desktop support location
        case .biometricAuthentication:
            return true // Most modern devices support biometrics
        case .multiWindow:
            return PlatformDetector.currentPlatform.isDesktop
        case .systemTray:
            return PlatformDetector.currentPlatform.isDesktop
        case .pushNotifications:
            return PlatformDetector.currentPlatform.isMobile
        case .widgets:
            return PlatformDetector.currentPlatform.isMobile
        case .shareExtension:
            return PlatformDetector.currentPlatform.isMobile
        case .appClips:
            return PlatformDetector.currentPlatform == .iOS
        case .instantApps:
            return PlatformDetector.currentPlatform == .android
        case .cloudSync:
            return true // All platforms support cloud sync
        case .offlineMode:
            return true // All platforms support offline mode
        }
    }
}

// MARK: - Platform Features

public enum PlatformFeature {
    case notifications
    case backgroundSync
    case fileSystemAccess
    case cameraAccess
    case microphoneAccess
    case locationServices
    case biometricAuthentication
    case multiWindow
    case systemTray
    case pushNotifications
    case widgets
    case shareExtension
    case appClips
    case instantApps
    case cloudSync
    case offlineMode
}

// MARK: - Platform-Specific Extensions

public extension Platform {
    var notificationServiceType: NotificationServiceType {
        switch self {
        case .windows: return .windowsToast
        case .linux: return .freedesktop
        case .macOS: return .userNotifications
        case .iOS: return .userNotifications
        case .android: return .firebaseCloudMessaging
        case .unknown: return .basic
        }
    }
    
    var fileSystemType: FileSystemType {
        switch self {
        case .windows: return .ntfs
        case .linux: return .ext4
        case .macOS: return .apfs
        case .iOS: return .apfs
        case .android: return .ext4
        case .unknown: return .generic
        }
    }
    
    var defaultBrowser: BrowserType {
        switch self {
        case .windows: return .edge
        case .linux: return .firefox
        case .macOS: return .safari
        case .iOS: return .safari
        case .android: return .chrome
        case .unknown: return .webView
        }
    }
}

// MARK: - Supporting Types

public enum NotificationServiceType {
    case windowsToast
    case freedesktop
    case userNotifications
    case firebaseCloudMessaging
    case basic
}

public enum FileSystemType {
    case ntfs
    case ext4
    case apfs
    case fat32
    case exfat
    case generic
}

public enum BrowserType {
    case safari
    case chrome
    case firefox
    case edge
    case webView
    case custom(String)
}

// MARK: - Platform-Specific Conditional Compilation

public struct PlatformCompilerFlags {
    
    public static var isWindows: Bool {
        #if os(Windows)
        return true
        #else
        return false
        #endif
    }
    
    public static var isLinux: Bool {
        #if os(Linux)
        return true
        #else
        return false
        #endif
    }
    
    public static var isMacOS: Bool {
        #if os(macOS)
        return true
        #else
        return false
        #endif
    }
    
    public static var isIOS: Bool {
        #if os(iOS)
        return true
        #else
        return false
        #endif
    }
    
    public static var isAndroid: Bool {
        #if os(Android)
        return true
        #else
        return false
        #endif
    }
    
    public static var isMobile: Bool {
        return isIOS || isAndroid
    }
    
    public static var isDesktop: Bool {
        return isWindows || isLinux || isMacOS
    }
}