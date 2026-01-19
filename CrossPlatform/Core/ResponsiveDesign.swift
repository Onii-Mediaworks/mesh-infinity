//
//  ResponsiveDesign.swift
//  NetInfinity Cross-Platform Core
//
//

import SwiftUI

// MARK: - Responsive Design System

/// Cross-platform responsive design system
public struct ResponsiveDesign {
    
    // MARK: - Breakpoints
    
    public enum Breakpoint: CGFloat {
        case xSmall = 320    // Mobile phones (portrait)
        case small = 480     // Mobile phones (landscape)
        case medium = 768    // Tablets (portrait)
        case large = 1024    // Tablets (landscape)/Small desktops
        case xLarge = 1280   // Desktops
        case xxLarge = 1440  // Large desktops
        case xxxLarge = 1920 // Extra large desktops
    }
    
    // MARK: - Screen Size Categories
    
    public enum ScreenSize {
        case mobile
        case tablet
        case desktop
        case largeDesktop
    }
    
    // MARK: - Device Orientation
    
    public enum DeviceOrientation {
        case portrait
        case landscape
        case square
        case unknown
    }
    
    // MARK: - Current Screen Information
    
    public static var currentScreenSize: ScreenSize {
        let width = currentScreenWidth
        
        if width < Breakpoint.medium.rawValue {
            return .mobile
        } else if width < Breakpoint.xLarge.rawValue {
            return .tablet
        } else if width < Breakpoint.xxLarge.rawValue {
            return .desktop
        } else {
            return .largeDesktop
        }
    }
    
    public static var currentScreenWidth: CGFloat {
        #if os(iOS) || os(Android)
        return UIScreen.main.bounds.width
        #elseif os(macOS) || os(Windows) || os(Linux)
        return NSScreen.main?.frame.width ?? 1024
        #else
        return 1024 // Default fallback
        #endif
    }
    
    public static var currentScreenHeight: CGFloat {
        #if os(iOS) || os(Android)
        return UIScreen.main.bounds.height
        #elseif os(macOS) || os(Windows) || os(Linux)
        return NSScreen.main?.frame.height ?? 768
        #else
        return 768 // Default fallback
        #endif
    }
    
    public static var currentOrientation: DeviceOrientation {
        let width = currentScreenWidth
        let height = currentScreenHeight
        
        if width > height {
            return .landscape
        } else if height > width {
            return .portrait
        } else {
            return .square
        }
    }
    
    // MARK: - Responsive Layout Utilities
    
    public static func isScreenSize(_ size: ScreenSize) -> Bool {
        return currentScreenSize == size
    }
    
    public static func isScreenSizeOrLarger(_ size: ScreenSize) -> Bool {
        switch (currentScreenSize, size) {
        case (.mobile, .mobile): return true
        case (.tablet, .mobile): return true
        case (.tablet, .tablet): return true
        case (.desktop, .mobile): return true
        case (.desktop, .tablet): return true
        case (.desktop, .desktop): return true
        case (.largeDesktop, _): return true
        default: return false
        }
    }
    
    public static func isScreenSizeOrSmaller(_ size: ScreenSize) -> Bool {
        switch (currentScreenSize, size) {
        case (.mobile, .mobile): return true
        case (.tablet, .tablet): return true
        case (.tablet, .mobile): return true
        case (.desktop, .desktop): return true
        case (.desktop, .tablet): return true
        case (.desktop, .mobile): return true
        case (.largeDesktop, .largeDesktop): return true
        default: return false
        }
    }
    
    // MARK: - Responsive Values
    
    public static func responsiveValue<
        T: Numeric & Comparable
    >(
        mobile: T,
        tablet: T,
        desktop: T,
        largeDesktop: T? = nil
    ) -> T {
        switch currentScreenSize {
        case .mobile: return mobile
        case .tablet: return tablet
        case .desktop: return desktop
        case .largeDesktop: return largeDesktop ?? desktop
        }
    }
    
    public static func responsiveFont(
        mobile: Font,
        tablet: Font,
        desktop: Font,
        largeDesktop: Font? = nil
    ) -> Font {
        switch currentScreenSize {
        case .mobile: return mobile
        case .tablet: return tablet
        case .desktop: return desktop
        case .largeDesktop: return largeDesktop ?? desktop
        }
    }
    
    public static func responsivePadding(
        mobile: CGFloat,
        tablet: CGFloat,
        desktop: CGFloat,
        largeDesktop: CGFloat? = nil
    ) -> CGFloat {
        return responsiveValue(
            mobile: mobile,
            tablet: tablet,
            desktop: desktop,
            largeDesktop: largeDesktop
        )
    }
    
    public static func responsiveSpacing(
        mobile: CGFloat,
        tablet: CGFloat,
        desktop: CGFloat,
        largeDesktop: CGFloat? = nil
    ) -> CGFloat {
        return responsiveValue(
            mobile: mobile,
            tablet: tablet,
            desktop: desktop,
            largeDesktop: largeDesktop
        )
    }
    
    // MARK: - Layout Configuration
    
    public static func layoutConfiguration() -> LayoutConfig {
        switch currentScreenSize {
        case .mobile:
            return MobileLayoutConfig()
        case .tablet:
            return TabletLayoutConfig()
        case .desktop:
            return DesktopLayoutConfig()
        case .largeDesktop:
            return LargeDesktopLayoutConfig()
        }
    }
    
    // MARK: - Navigation Configuration
    
    public static func navigationConfiguration() -> NavigationConfig {
        switch currentScreenSize {
        case .mobile:
            return MobileNavigationConfig()
        case .tablet:
            return TabletNavigationConfig()
        case .desktop:
            return DesktopNavigationConfig()
        case .largeDesktop:
            return LargeDesktopNavigationConfig()
        }
    }
    
    // MARK: - Input Method Configuration
    
    public static func inputMethodConfiguration() -> InputMethodConfig {
        if PlatformDetector.isTouchInterface {
            return TouchInputConfig()
        } else {
            return PointerInputConfig()
        }
    }
}

// MARK: - Layout Configuration Protocols

public protocol LayoutConfig {
    var columnCount: Int { get }
    var itemSize: CGSize { get }
    var spacing: CGFloat { get }
    var padding: CGFloat { get }
    var cornerRadius: CGFloat { get }
    var maxWidth: CGFloat? { get }
}

public protocol NavigationConfig {
    var navigationStyle: NavigationStyle { get }
    var sidebarWidth: CGFloat { get }
    var sidebarVisible: Bool { get }
    var toolbarVisible: Bool { get }
    var usesTabs: Bool { get }
}

public protocol InputMethodConfig {
    var inputType: InputType { get }
    var buttonSize: CGSize { get }
    var touchTargetSize: CGSize { get }
    var hoverEffectsEnabled: Bool { get }
    var longPressDuration: TimeInterval { get }
}

// MARK: - Layout Configurations

public struct MobileLayoutConfig: LayoutConfig {
    public let columnCount: Int = 1
    public let itemSize: CGSize = CGSize(width: 340, height: 200)
    public let spacing: CGFloat = 12
    public let padding: CGFloat = 16
    public let cornerRadius: CGFloat = 12
    public let maxWidth: CGFloat? = 400
}

public struct TabletLayoutConfig: LayoutConfig {
    public let columnCount: Int = 2
    public let itemSize: CGSize = CGSize(width: 300, height: 220)
    public let spacing: CGFloat = 16
    public let padding: CGFloat = 20
    public let cornerRadius: CGFloat = 12
    public let maxWidth: CGFloat? = 800
}

public struct DesktopLayoutConfig: LayoutConfig {
    public let columnCount: Int = 3
    public let itemSize: CGSize = CGSize(width: 280, height: 240)
    public let spacing: CGFloat = 20
    public let padding: CGFloat = 24
    public let cornerRadius: CGFloat = 12
    public let maxWidth: CGFloat? = 1200
}

public struct LargeDesktopLayoutConfig: LayoutConfig {
    public let columnCount: Int = 4
    public let itemSize: CGSize = CGSize(width: 260, height: 260)
    public let spacing: CGFloat = 24
    public let padding: CGFloat = 28
    public let cornerRadius: CGFloat = 12
    public let maxWidth: CGFloat? = 1600
}

// MARK: - Navigation Configurations

public struct MobileNavigationConfig: NavigationConfig {
    public let navigationStyle: NavigationStyle = .stack
    public let sidebarWidth: CGFloat = 280
    public let sidebarVisible: Bool = false
    public let toolbarVisible: Bool = true
    public let usesTabs: Bool = false
}

public struct TabletNavigationConfig: NavigationConfig {
    public let navigationStyle: NavigationStyle = .splitView
    public let sidebarWidth: CGFloat = 300
    public let sidebarVisible: Bool = true
    public let toolbarVisible: Bool = true
    public let usesTabs: Bool = false
}

public struct DesktopNavigationConfig: NavigationConfig {
    public let navigationStyle: NavigationStyle = .sidebar
    public let sidebarWidth: CGFloat = 240
    public let sidebarVisible: Bool = true
    public let toolbarVisible: Bool = true
    public let usesTabs: Bool = true
}

public struct LargeDesktopNavigationConfig: NavigationConfig {
    public let navigationStyle: NavigationStyle = .sidebar
    public let sidebarWidth: CGFloat = 280
    public let sidebarVisible: Bool = true
    public let toolbarVisible: Bool = true
    public let usesTabs: Bool = true
}

// MARK: - Input Method Configurations

public struct TouchInputConfig: InputMethodConfig {
    public let inputType: InputType = .touch
    public let buttonSize: CGSize = CGSize(width: 48, height: 48)
    public let touchTargetSize: CGSize = CGSize(width: 48, height: 48)
    public let hoverEffectsEnabled: Bool = false
    public let longPressDuration: TimeInterval = 0.5
}

public struct PointerInputConfig: InputMethodConfig {
    public let inputType: InputType = .pointer
    public let buttonSize: CGSize = CGSize(width: 32, height: 32)
    public let touchTargetSize: CGSize = CGSize(width: 44, height: 44)
    public let hoverEffectsEnabled: Bool = true
    public let longPressDuration: TimeInterval = 0.8
}

// MARK: - Supporting Types

public enum NavigationStyle {
    case stack
    case splitView
    case sidebar
    case tabbed
    case modal
}

public enum InputType {
    case touch
    case pointer
    case mixed
    case unknown
}

public enum FormFactor {
    case phone
    case phablet
    case tablet
    case laptop
    case desktop
    case tv
    case watch
    case unknown
}

// MARK: - Responsive View Modifiers

public struct ResponsiveModifier: ViewModifier {
    let mobile: AnyView
    let tablet: AnyView
    let desktop: AnyView
    let largeDesktop: AnyView?
    
    public init<
        Mobile: View,
        Tablet: View,
        Desktop: View,
        LargeDesktop: View
    >(
        mobile: Mobile,
        tablet: Tablet,
        desktop: Desktop,
        largeDesktop: LargeDesktop? = nil
    ) {
        self.mobile = AnyView(mobile)
        self.tablet = AnyView(tablet)
        self.desktop = AnyView(desktop)
        self.largeDesktop = largeDesktop.map { AnyView($0) }
    }
    
    public func body(content: Content) -> some View {
        switch ResponsiveDesign.currentScreenSize {
        case .mobile:
            mobile
        case .tablet:
            tablet
        case .desktop:
            desktop
        case .largeDesktop:
            largeDesktop ?? desktop
        }
    }
}

// MARK: - Responsive Stacks

public struct ResponsiveHStack<Content: View>: View {
    let content: Content
    let spacing: CGFloat
    let alignment: VerticalAlignment
    
    public init(
        spacing: CGFloat = 8,
        alignment: VerticalAlignment = .center,
        @ViewBuilder content: () -> Content
    ) {
        self.content = content()
        self.spacing = spacing
        self.alignment = alignment
    }
    
    public var body: some View {
        switch ResponsiveDesign.currentScreenSize {
        case .mobile:
            VStack(spacing: spacing) {
                content
            }
        case .tablet, .desktop, .largeDesktop:
            HStack(alignment: alignment, spacing: spacing) {
                content
            }
        }
    }
}

public struct ResponsiveVStack<Content: View>: View {
    let content: Content
    let spacing: CGFloat
    let alignment: HorizontalAlignment
    
    public init(
        spacing: CGFloat = 8,
        alignment: HorizontalAlignment = .center,
        @ViewBuilder content: () -> Content
    ) {
        self.content = content()
        self.spacing = spacing
        self.alignment = alignment
    }
    
    public var body: some View {
        switch ResponsiveDesign.currentScreenSize {
        case .mobile, .tablet:
            VStack(alignment: alignment, spacing: spacing) {
                content
            }
        case .desktop, .largeDesktop:
            HStack(alignment: .center, spacing: spacing) {
                content
            }
        }
    }
}

// MARK: - Responsive Grid

public struct ResponsiveGrid<Content: View, Item: Identifiable>: View {
    let items: [Item]
    let content: (Item) -> Content
    
    public init(
        items: [Item],
        @ViewBuilder content: @escaping (Item) -> Content
    ) {
        self.items = items
        self.content = content
    }
    
    public var body: some View {
        let layoutConfig = ResponsiveDesign.layoutConfiguration()
        
        return LazyVGrid(
            columns: Array(repeating: .init(.flexible(), spacing: layoutConfig.spacing), 
                          count: layoutConfig.columnCount),
            spacing: layoutConfig.spacing
        ) {
            ForEach(items) { item in
                content(item)
                    .frame(width: layoutConfig.itemSize.width, 
                           height: layoutConfig.itemSize.height)
            }
        }
        .padding(layoutConfig.padding)
    }
}

// MARK: - View Extensions

extension View {
    
    public func responsiveModifier<
        Mobile: View,
        Tablet: View,
        Desktop: View,
        LargeDesktop: View
    >(
        mobile: Mobile,
        tablet: Tablet,
        desktop: Desktop,
        largeDesktop: LargeDesktop? = nil
    ) -> some View {
        modifier(ResponsiveModifier(
            mobile: mobile,
            tablet: tablet,
            desktop: desktop,
            largeDesktop: largeDesktop
        ))
    }
    
    public func responsiveFont(
        mobile: Font,
        tablet: Font,
        desktop: Font,
        largeDesktop: Font? = nil
    ) -> some View {
        self.font(ResponsiveDesign.responsiveFont(
            mobile: mobile,
            tablet: tablet,
            desktop: desktop,
            largeDesktop: largeDesktop
        ))
    }
    
    public func responsivePadding(
        mobile: CGFloat,
        tablet: CGFloat,
        desktop: CGFloat,
        largeDesktop: CGFloat? = nil
    ) -> some View {
        self.padding(ResponsiveDesign.responsivePadding(
            mobile: mobile,
            tablet: tablet,
            desktop: desktop,
            largeDesktop: largeDesktop
        ))
    }
    
    public func responsiveFrame(
        mobile: CGSize,
        tablet: CGSize,
        desktop: CGSize,
        largeDesktop: CGSize? = nil
    ) -> some View {
        let size = ResponsiveDesign.responsiveValue(
            mobile: mobile.width,
            tablet: tablet.width,
            desktop: desktop.width,
            largeDesktop: largeDesktop?.width
        )
        
        return self.frame(width: size, height: size)
    }
    
    public func responsiveCornerRadius(
        mobile: CGFloat,
        tablet: CGFloat,
        desktop: CGFloat,
        largeDesktop: CGFloat? = nil
    ) -> some View {
        self.cornerRadius(ResponsiveDesign.responsiveValue(
            mobile: mobile,
            tablet: tablet,
            desktop: desktop,
            largeDesktop: largeDesktop
        ))
    }
}

// MARK: - Preview

#Preview {
    VStack(spacing: 20) {
        Text("Responsive Design Demo")
            .responsiveFont(
                mobile: .title,
                tablet: .title2,
                desktop: .largeTitle
            )
        
        ResponsiveHStack {
            Color.red.frame(width: 50, height: 50)
            Color.green.frame(width: 50, height: 50)
            Color.blue.frame(width: 50, height: 50)
        }
        .frame(height: 100)
        
        ResponsiveVStack {
            Color.purple.frame(width: 50, height: 50)
            Color.orange.frame(width: 50, height: 50)
            Color.yellow.frame(width: 50, height: 50)
        }
        .frame(height: 100)
        
        Text("Current Screen Size: \(ResponsiveDesign.currentScreenSize)")
        Text("Current Platform: \(PlatformDetector.currentPlatform.name)")
        Text("Is Mobile: \(String(PlatformDetector.isMobilePlatform))")
        Text("Is Desktop: \(String(PlatformDetector.isDesktopPlatform))")
    }
    .padding()
}