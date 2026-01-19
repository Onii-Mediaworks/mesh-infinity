//
//  AccessibilityUtils.swift
//  NetInfinity
//
//

import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

// MARK: - Accessibility Utilities

/// Accessibility utilities for NetInfinity
struct AccessibilityUtils {
    
    // MARK: - Screen Reader Announcements
    
    static func announce(_ message: String) {
        #if canImport(UIKit)
        UIAccessibility.post(notification: .announcement, argument: message)
        #endif
    }
    
    static func announcePageLoaded(_ pageName: String) {
        announce("Page loaded: \(pageName)")
    }
    
    static func announceActionCompleted(_ action: String) {
        announce("Action completed: \(action)")
    }
    
    static func announceError(_ error: String) {
        announce("Error: \(error)")
    }
    
    // MARK: - Accessibility Modifiers
    
    static func accessibilityLabel(for text: String, context: String? = nil) -> String {
        var label = text
        if let context = context {
            label = "\(context): \(text)"
        }
        return label
    }
    
    static func accessibilityHint(for action: String) -> String {
        return "Double tap to \(action)"
    }
    
    static func accessibilityValue(for value: String, context: String? = nil) -> String {
        var label = value
        if let context = context {
            label = "\(context): \(value)"
        }
        return label
    }
    
    // MARK: - Accessibility Identifiers
    
    static func accessibilityIdentifier(for element: String, context: String? = nil) -> String {
        var identifier = element
        if let context = context {
            identifier = "\(context)_\(element)"
        }
        return identifier
    }
    
    // MARK: - Accessibility Traits
    
    static func isButton() -> AccessibilityTraits {
        return .isButton
    }
    
    static func isHeader() -> AccessibilityTraits {
        return .isHeader
    }
    
    static func isSelected() -> AccessibilityTraits {
        return .isSelected
    }
    
    static func isLink() -> AccessibilityTraits {
        return .isLink
    }
    
    static func isImage() -> AccessibilityTraits {
        return .isImage
    }
    
    // MARK: - Dynamic Type Support
    
    static func scaledFont(_ font: Font, for textStyle: Font.TextStyle) -> Font {
        return font
    }
    
    static func isBoldTextEnabled() -> Bool {
        #if canImport(UIKit)
        return UIAccessibility.isBoldTextEnabled
        #else
        return false
        #endif
    }
    
    static func isReduceMotionEnabled() -> Bool {
        #if canImport(UIKit)
        return UIAccessibility.isReduceMotionEnabled
        #else
        return false
        #endif
    }
    
    static func isReduceTransparencyEnabled() -> Bool {
        #if canImport(UIKit)
        return UIAccessibility.isReduceTransparencyEnabled
        #else
        return false
        #endif
    }
    
    static func isDarkerSystemColorsEnabled() -> Bool {
        #if canImport(UIKit)
        return UIAccessibility.isDarkerSystemColorsEnabled
        #else
        return false
        #endif
    }
    
    // MARK: - Accessibility View Modifiers
    
    static func accessibilityModifier(
        label: String? = nil,
        hint: String? = nil,
        value: String? = nil,
        identifier: String? = nil,
        traits: AccessibilityTraits? = nil,
        isHidden: Bool = false
    ) -> some ViewModifier {
        return AccessibilityModifier(
            label: label,
            hint: hint,
            value: value,
            identifier: identifier,
            traits: traits,
            isHidden: isHidden
        )
    }
}

// MARK: - Accessibility Modifier

struct AccessibilityModifier: ViewModifier {
    let label: String?
    let hint: String?
    let value: String?
    let identifier: String?
    let traits: AccessibilityTraits?
    let isHidden: Bool
    
    func body(content: Content) -> some View {
        content
            .accessibilityLabel(label ?? "")
            .accessibilityHint(hint ?? "")
            .accessibilityValue(value ?? "")
            .accessibilityIdentifier(identifier ?? "")
            .accessibilityAddTraits(traits ?? [])
            .accessibilityHidden(isHidden)
    }
}

// MARK: - Accessibility Extensions

extension View {
    func accessibleButton(_ label: String, hint: String? = nil) -> some View {
        self
            .accessibilityLabel(label)
            .accessibilityHint(hint ?? "Double tap to activate")
            .accessibilityAddTraits(.isButton)
    }
    
    func accessibleHeader(_ level: Int = 1) -> some View {
        self
            .accessibilityAddTraits(.isHeader)
            .accessibilitySortPriority(Double(level))
    }
    
    func accessibleText(_ label: String, isImportant: Bool = false) -> some View {
        self
            .accessibilityLabel(label)
            .accessibilityAddTraits(isImportant ? .isStaticText : [])
    }
    
    func accessibleImage(_ description: String) -> some View {
        self
            .accessibilityLabel(description)
            .accessibilityAddTraits(.isImage)
    }
    
    func accessibleHidden(_ isHidden: Bool = true) -> some View {
        self
            .accessibilityHidden(isHidden)
    }
    
    func accessibleIdentifier(_ identifier: String) -> some View {
        self
            .accessibilityIdentifier(identifier)
    }
}

// MARK: - Internationalization Utilities

struct InternationalizationUtils {
    
    // MARK: - Language Support
    
    static func currentLanguage() -> String {
        return Locale.current.languageCode ?? "en"
    }
    
    static func isRTLLanguage() -> Bool {
        let languageCode = Locale.current.languageCode ?? "en"
        return Locale.characterDirection(forLanguage: languageCode) == .rightToLeft
    }
    
    static func preferredLanguages() -> [String] {
        return Locale.preferredLanguages.map { 
            Locale(identifier: $0).languageCode ?? "en" 
        }
    }
    
    // MARK: - Localized Strings
    
    static func localizedString(_ key: String, 
                               bundle: Bundle = .main,
                               comment: String = "") -> String {
        return NSLocalizedString(key, bundle: bundle, comment: comment)
    }
    
    static func localizedString(_ key: String,
                               arguments: CVarArg...,
                               bundle: Bundle = .main,
                               comment: String = "") -> String {
        let format = localizedString(key, bundle: bundle, comment: comment)
        return String(format: format, arguments: arguments)
    }
    
    // MARK: - Date Formatting
    
    static func localizedDateString(_ date: Date,
                                   style: DateFormatter.Style = .medium,
                                   timeStyle: DateFormatter.Style = .none) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = style
        formatter.timeStyle = timeStyle
        formatter.locale = Locale.current
        return formatter.string(from: date)
    }
    
    static func localizedRelativeDateString(_ date: Date) -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.locale = Locale.current
        return formatter.localizedString(for: date, relativeTo: Date())
    }
    
    // MARK: - Number Formatting
    
    static func localizedNumberString(_ number: NSNumber,
                                     style: NumberFormatter.Style = .decimal) -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = style
        formatter.locale = Locale.current
        return formatter.string(from: number) ?? "\(number)"
    }
    
    // MARK: - Measurement Formatting
    
    static func localizedMeasurementString(_ measurement: Measurement<Unit>,
                                         unitStyle: MeasurementFormatter.UnitStyle = .medium,
                                         numberStyle: NumberFormatter.Style = .decimal) -> String {
        let formatter = MeasurementFormatter()
        formatter.locale = Locale.current
        formatter.unitStyle = unitStyle
        formatter.numberFormatter.numberStyle = numberStyle
        return formatter.string(from: measurement)
    }
    
    // MARK: - String Direction
    
    static func stringDirection(for text: String) -> NSLocale.LanguageDirection {
        let languageCode = Locale.current.languageCode ?? "en"
        return Locale.characterDirection(forLanguage: languageCode)
    }
}

// MARK: - Accessibility + Internationalization Combined

struct A11yUtils {
    
    static func localizedAccessibilityLabel(_ key: String,
                                          bundle: Bundle = .main,
                                          comment: String = "") -> String {
        return InternationalizationUtils.localizedString(key, bundle: bundle, comment: comment)
    }
    
    static func localizedAccessibilityHint(_ key: String,
                                          bundle: Bundle = .main,
                                          comment: String = "") -> String {
        return InternationalizationUtils.localizedString(key, bundle: bundle, comment: comment)
    }
    
    static func localizedAccessibilityValue(_ key: String,
                                           bundle: Bundle = .main,
                                           comment: String = "") -> String {
        return InternationalizationUtils.localizedString(key, bundle: bundle, comment: comment)
    }
    
    static func announceLocalized(_ key: String,
                                 bundle: Bundle = .main,
                                 comment: String = "") {
        let message = InternationalizationUtils.localizedString(key, bundle: bundle, comment: comment)
        AccessibilityUtils.announce(message)
    }
}

// MARK: - Preview

#Preview {
    VStack(spacing: 20) {
        Text("Accessibility Demo")
            .font(.largeTitle)
            .accessibleHeader(1)
        
        Button("Click Me") {}
            .accessibleButton("Example button", hint: "Opens a new screen")
        
        Image(systemName: "photo")
            .resizable()
            .frame(width: 100, height: 100)
            .accessibleImage("Photo")
        
        Text("Important information")
            .accessibleText("Important information", isImportant: true)
    }
    .padding()
}
