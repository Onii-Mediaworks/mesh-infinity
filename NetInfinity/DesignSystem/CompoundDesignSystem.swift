//
//  CompoundDesignSystem.swift
//  NetInfinity
//
//

import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

struct Shadow {
    let color: Color
    let radius: CGFloat
    let x: CGFloat
    let y: CGFloat
}


// MARK: - Compound Design System

/// Compound-like design system for NetInfinity
/// Inspired by Compound design system with Material Design 3 principles
struct CompoundDesignSystem {
    
    // MARK: - Colors
    
    struct Colors {
        // Primary palette
        static let primary = Color("PrimaryColor", bundle: .main)
        static let primaryVariant = Color("PrimaryVariant", bundle: .main)
        static let onPrimary = Color("OnPrimary", bundle: .main)
        
        // Secondary palette
        static let secondary = Color("SecondaryColor", bundle: .main)
        static let secondaryVariant = Color("SecondaryVariant", bundle: .main)
        static let onSecondary = Color("OnSecondary", bundle: .main)
        
        // Surface colors
        static let surface = Color("Surface", bundle: .main)
        static let onSurface = Color("OnSurface", bundle: .main)
        static let surfaceVariant = Color("SurfaceVariant", bundle: .main)
        
        // Background colors
        static let background = Color("Background", bundle: .main)
        static let onBackground = Color("OnBackground", bundle: .main)
        
        // Error colors
        static let error = Color("Error", bundle: .main)
        static let onError = Color("OnError", bundle: .main)
        
        // Success colors
        static let success = Color("Success", bundle: .main)
        static let onSuccess = Color("OnSuccess", bundle: .main)
        
        // Warning colors
        static let warning = Color("Warning", bundle: .main)
        static let onWarning = Color("OnWarning", bundle: .main)
        
        // Info colors
        static let info = Color("Info", bundle: .main)
        static let onInfo = Color("OnInfo", bundle: .main)
        
        // Neutral colors
        static let neutral = Color("Neutral", bundle: .main)
        static let neutralVariant = Color("NeutralVariant", bundle: .main)
        
        // Gradient colors
        static let primaryGradient = LinearGradient(
            gradient: Gradient(colors: [primary, primaryVariant]),
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
        
        static let secondaryGradient = LinearGradient(
            gradient: Gradient(colors: [secondary, secondaryVariant]),
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
    }
    
    // MARK: - Typography
    
    struct Typography {
        // Display typography
        static func displayLarge() -> Font {
            .system(size: 57, weight: .regular, design: .default)
        }
        
        static func displayMedium() -> Font {
            .system(size: 45, weight: .regular, design: .default)
        }
        
        static func displaySmall() -> Font {
            .system(size: 36, weight: .regular, design: .default)
        }
        
        // Headline typography
        static func headlineLarge() -> Font {
            .system(size: 32, weight: .bold, design: .default)
        }
        
        static func headlineMedium() -> Font {
            .system(size: 28, weight: .bold, design: .default)
        }
        
        static func headlineSmall() -> Font {
            .system(size: 24, weight: .bold, design: .default)
        }
        
        // Title typography
        static func titleLarge() -> Font {
            .system(size: 22, weight: .semibold, design: .default)
        }
        
        static func titleMedium() -> Font {
            .system(size: 18, weight: .semibold, design: .default)
        }
        
        static func titleSmall() -> Font {
            .system(size: 16, weight: .semibold, design: .default)
        }
        
        // Body typography
        static func bodyLarge() -> Font {
            .system(size: 16, weight: .regular, design: .default)
        }
        
        static func bodyMedium() -> Font {
            .system(size: 14, weight: .regular, design: .default)
        }
        
        static func bodySmall() -> Font {
            .system(size: 12, weight: .regular, design: .default)
        }
        
        // Label typography
        static func labelLarge() -> Font {
            .system(size: 14, weight: .medium, design: .default)
        }
        
        static func labelMedium() -> Font {
            .system(size: 12, weight: .medium, design: .default)
        }
        
        static func labelSmall() -> Font {
            .system(size: 11, weight: .medium, design: .default)
        }
    }
    
    // MARK: - Spacing
    
    struct Spacing {
        static let none: CGFloat = 0
        static let xxxxSmall: CGFloat = 2
        static let xxxSmall: CGFloat = 4
        static let xxSmall: CGFloat = 8
        static let xSmall: CGFloat = 12
        static let small: CGFloat = 16
        static let medium: CGFloat = 20
        static let large: CGFloat = 24
        static let xLarge: CGFloat = 28
        static let xxLarge: CGFloat = 32
        static let xxxLarge: CGFloat = 40
        static let xxxxLarge: CGFloat = 48
        static let huge: CGFloat = 56
        static let xHuge: CGFloat = 64
    }
    
    // MARK: - Corner Radius
    
    struct CornerRadius {
        static let none: CGFloat = 0
        static let xSmall: CGFloat = 4
        static let small: CGFloat = 8
        static let medium: CGFloat = 12
        static let large: CGFloat = 16
        static let xLarge: CGFloat = 20
        static let full: CGFloat = .infinity
    }
    
    // MARK: - Shadows
    
    struct Shadows {
        static let small = Shadow(
            color: Colors.neutral.opacity(0.1),
            radius: 2,
            x: 0,
            y: 1
        )
        
        static let medium = Shadow(
            color: Colors.neutral.opacity(0.1),
            radius: 4,
            x: 0,
            y: 2
        )
        
        static let large = Shadow(
            color: Colors.neutral.opacity(0.1),
            radius: 8,
            x: 0,
            y: 4
        )
        
        static let xLarge = Shadow(
            color: Colors.neutral.opacity(0.1),
            radius: 12,
            x: 0,
            y: 6
        )
    }
    
    // MARK: - Elevation
    
    struct Elevation {
        static let level0: [Shadow] = []
        static let level1: [Shadow] = [Shadows.small]
        static let level2: [Shadow] = [Shadows.medium]
        static let level3: [Shadow] = [Shadows.large]
        static let level4: [Shadow] = [Shadows.xLarge]
        static let level5: [Shadow] = [Shadows.xLarge, Shadows.large]
    }
}

// MARK: - Compound Components

// Primary Button
struct PrimaryButton: View {
    let title: String
    let icon: String?
    let action: () -> Void
    let isLoading: Bool
    let isDisabled: Bool
    
    init(title: String, icon: String? = nil, isLoading: Bool = false, isDisabled: Bool = false, action: @escaping () -> Void) {
        self.title = title
        self.icon = icon
        self.isLoading = isLoading
        self.isDisabled = isDisabled
        self.action = action
    }
    
    var body: some View {
        Button(action: action) {
            HStack(spacing: CompoundDesignSystem.Spacing.xSmall) {
                if isLoading {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: .white))
                } else if let icon = icon {
                    Image(systemName: icon)
                        .font(CompoundDesignSystem.Typography.labelMedium())
                }
                
                Text(title)
                    .font(CompoundDesignSystem.Typography.labelLarge())
                    .frame(maxWidth: .infinity)
            }
            .padding(.vertical, CompoundDesignSystem.Spacing.small)
            .padding(.horizontal, CompoundDesignSystem.Spacing.large)
            .background(
                isDisabled ? 
                    CompoundDesignSystem.Colors.primary.opacity(0.3) :
                    CompoundDesignSystem.Colors.primary
            )
            .foregroundColor(isDisabled ? 
                CompoundDesignSystem.Colors.onPrimary.opacity(0.5) :
                CompoundDesignSystem.Colors.onPrimary
            )
            .cornerRadius(CompoundDesignSystem.CornerRadius.medium)
            .shadow(color: CompoundDesignSystem.Colors.primary.opacity(0.2), 
                    radius: 4, x: 0, y: 2)
        }
        .disabled(isDisabled || isLoading)
        .buttonStyle(PlainButtonStyle())
    }
}

// Secondary Button
struct SecondaryButton: View {
    let title: String
    let icon: String?
    let action: () -> Void
    let isLoading: Bool
    let isDisabled: Bool
    
    init(title: String, icon: String? = nil, isLoading: Bool = false, isDisabled: Bool = false, action: @escaping () -> Void) {
        self.title = title
        self.icon = icon
        self.isLoading = isLoading
        self.isDisabled = isDisabled
        self.action = action
    }
    
    var body: some View {
        Button(action: action) {
            HStack(spacing: CompoundDesignSystem.Spacing.xSmall) {
                if isLoading {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: CompoundDesignSystem.Colors.primary))
                } else if let icon = icon {
                    Image(systemName: icon)
                        .font(CompoundDesignSystem.Typography.labelMedium())
                }
                
                Text(title)
                    .font(CompoundDesignSystem.Typography.labelLarge())
                    .frame(maxWidth: .infinity)
            }
            .padding(.vertical, CompoundDesignSystem.Spacing.small)
            .padding(.horizontal, CompoundDesignSystem.Spacing.large)
            .background(
                isDisabled ? 
                    CompoundDesignSystem.Colors.surfaceVariant :
                    CompoundDesignSystem.Colors.surface
            )
            .foregroundColor(
                isDisabled ? 
                    CompoundDesignSystem.Colors.onSurface.opacity(0.5) :
                    CompoundDesignSystem.Colors.primary
            )
            .cornerRadius(CompoundDesignSystem.CornerRadius.medium)
            .overlay(
                RoundedRectangle(cornerRadius: CompoundDesignSystem.CornerRadius.medium)
                    .stroke(
                        isDisabled ? 
                            CompoundDesignSystem.Colors.neutralVariant.opacity(0.3) :
                            CompoundDesignSystem.Colors.neutralVariant,
                        lineWidth: 1
                    )
            )
        }
        .disabled(isDisabled || isLoading)
        .buttonStyle(PlainButtonStyle())
    }
}

// Text Button
struct TextButton: View {
    let title: String
    let icon: String?
    let action: () -> Void
    let isLoading: Bool
    let isDisabled: Bool
    
    init(title: String, icon: String? = nil, isLoading: Bool = false, isDisabled: Bool = false, action: @escaping () -> Void) {
        self.title = title
        self.icon = icon
        self.isLoading = isLoading
        self.isDisabled = isDisabled
        self.action = action
    }
    
    var body: some View {
        Button(action: action) {
            HStack(spacing: CompoundDesignSystem.Spacing.xSmall) {
                if isLoading {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: CompoundDesignSystem.Colors.primary))
                } else if let icon = icon {
                    Image(systemName: icon)
                        .font(CompoundDesignSystem.Typography.labelMedium())
                }
                
                Text(title)
                    .font(CompoundDesignSystem.Typography.labelLarge())
            }
            .padding(.vertical, CompoundDesignSystem.Spacing.xSmall)
            .padding(.horizontal, CompoundDesignSystem.Spacing.medium)
            .foregroundColor(
                isDisabled ? 
                    CompoundDesignSystem.Colors.primary.opacity(0.5) :
                    CompoundDesignSystem.Colors.primary
            )
        }
        .disabled(isDisabled || isLoading)
        .buttonStyle(PlainButtonStyle())
    }
}

// Icon Button
struct IconButton: View {
    let icon: String
    let size: IconButtonSize
    let action: () -> Void
    let isLoading: Bool
    let isDisabled: Bool
    
    enum IconButtonSize {
        case small, medium, large
        
        var iconSize: CGFloat {
            switch self {
            case .small: return 16
            case .medium: return 20
            case .large: return 24
            }
        }
        
        var padding: CGFloat {
            switch self {
            case .small: return 6
            case .medium: return 8
            case .large: return 10
            }
        }
    }
    
    init(icon: String, size: IconButtonSize = .medium, isLoading: Bool = false, isDisabled: Bool = false, action: @escaping () -> Void) {
        self.icon = icon
        self.size = size
        self.isLoading = isLoading
        self.isDisabled = isDisabled
        self.action = action
    }
    
    var body: some View {
        Button(action: action) {
            if isLoading {
                ProgressView()
                    .progressViewStyle(CircularProgressViewStyle(tint: CompoundDesignSystem.Colors.onPrimary))
            } else {
                Image(systemName: icon)
                    .font(.system(size: size.iconSize))
                    .frame(width: size.iconSize + size.padding * 2, 
                           height: size.iconSize + size.padding * 2)
            }
        }
        .background(
            isDisabled ? 
                CompoundDesignSystem.Colors.primary.opacity(0.3) :
                CompoundDesignSystem.Colors.primary
        )
        .foregroundColor(
            isDisabled ? 
                CompoundDesignSystem.Colors.onPrimary.opacity(0.5) :
                CompoundDesignSystem.Colors.onPrimary
        )
        .cornerRadius(CompoundDesignSystem.CornerRadius.full)
        .disabled(isDisabled || isLoading)
        .buttonStyle(PlainButtonStyle())
    }
}

// Card Component
struct CompoundCard<Content: View>: View {
    let content: Content
    let elevation: [Shadow]
    let backgroundColor: Color
    let cornerRadius: CGFloat
    let padding: CGFloat
    
    init(elevation: [Shadow] = CompoundDesignSystem.Elevation.level1,
         backgroundColor: Color = CompoundDesignSystem.Colors.surface,
         cornerRadius: CGFloat = CompoundDesignSystem.CornerRadius.medium,
         padding: CGFloat = CompoundDesignSystem.Spacing.medium,
         @ViewBuilder content: () -> Content) {
        self.content = content()
        self.elevation = elevation
        self.backgroundColor = backgroundColor
        self.cornerRadius = cornerRadius
        self.padding = padding
    }
    
    var body: some View {
        content
            .padding(padding)
            .background(backgroundColor)
            .cornerRadius(cornerRadius)
            .shadow(color: elevation.first?.color ?? .clear, 
                    radius: elevation.first?.radius ?? 0, 
                    x: elevation.first?.x ?? 0, 
                    y: elevation.first?.y ?? 0)
    }
}

// Text Field Component
struct CompoundTextField: View {
    let placeholder: String
    let icon: String?
    @Binding var text: String
    let isSecure: Bool
    let keyboardType: PlatformKeyboardType
    let isDisabled: Bool
    let errorMessage: String?
    
    init(placeholder: String, 
         icon: String? = nil,
         text: Binding<String>,
         isSecure: Bool = false,
         keyboardType: PlatformKeyboardType = .default,
         isDisabled: Bool = false,
         errorMessage: String? = nil) {
        self.placeholder = placeholder
        self.icon = icon
        self._text = text
        self.isSecure = isSecure
        self.keyboardType = keyboardType
        self.isDisabled = isDisabled
        self.errorMessage = errorMessage
    }
    
    var body: some View {
        VStack(alignment: .leading, spacing: CompoundDesignSystem.Spacing.xxxSmall) {
            HStack(spacing: CompoundDesignSystem.Spacing.xSmall) {
                if let icon = icon {
                    Image(systemName: icon)
                        .foregroundColor(
                            isDisabled ? 
                                CompoundDesignSystem.Colors.neutralVariant.opacity(0.5) :
                                CompoundDesignSystem.Colors.neutralVariant
                        )
                }
                
                if isSecure {
                    applyKeyboardType(
                        SecureField(placeholder, text: $text)
                            .font(CompoundDesignSystem.Typography.bodyMedium())
                            .disabled(isDisabled)
                            .foregroundColor(
                                isDisabled ? 
                                    CompoundDesignSystem.Colors.onSurface.opacity(0.5) :
                                    CompoundDesignSystem.Colors.onSurface
                            )
                    )
                } else {
                    applyKeyboardType(
                        TextField(placeholder, text: $text)
                            .font(CompoundDesignSystem.Typography.bodyMedium())
                            .disabled(isDisabled)
                            .foregroundColor(
                                isDisabled ? 
                                    CompoundDesignSystem.Colors.onSurface.opacity(0.5) :
                                    CompoundDesignSystem.Colors.onSurface
                            )
                    )
                }
                
                if !text.isEmpty {
                    Button(action: { text = "" }) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(CompoundDesignSystem.Colors.neutralVariant)
                    }
                }
            }
            .padding(CompoundDesignSystem.Spacing.medium)
            .background(
                isDisabled ? 
                    CompoundDesignSystem.Colors.surfaceVariant.opacity(0.5) :
                    CompoundDesignSystem.Colors.surface
            )
            .cornerRadius(CompoundDesignSystem.CornerRadius.small)
            .overlay(
                RoundedRectangle(cornerRadius: CompoundDesignSystem.CornerRadius.small)
                    .stroke(
                        errorMessage != nil ? 
                            CompoundDesignSystem.Colors.error :
                            CompoundDesignSystem.Colors.neutralVariant,
                        lineWidth: 1
                    )
            )
            
            if let errorMessage = errorMessage {
                Text(errorMessage)
                    .font(CompoundDesignSystem.Typography.labelSmall())
                    .foregroundColor(CompoundDesignSystem.Colors.error)
                    .padding(.horizontal, CompoundDesignSystem.Spacing.xSmall)
            }
        }
    }

    private func applyKeyboardType<T: View>(_ view: T) -> some View {
        #if canImport(UIKit)
        return view.keyboardType(keyboardType)
        #else
        return view
        #endif
    }
}

// Avatar Component
struct CompoundAvatar: View {
    let imageUrl: String?
    let name: String
    let size: AvatarSize
    let isOnline: Bool
    
    enum AvatarSize {
        case xSmall, small, medium, large, xLarge
        
        var dimension: CGFloat {
            switch self {
            case .xSmall: return 24
            case .small: return 32
            case .medium: return 40
            case .large: return 48
            case .xLarge: return 56
            }
        }
        
        var fontSize: CGFloat {
            switch self {
            case .xSmall: return 10
            case .small: return 12
            case .medium: return 14
            case .large: return 16
            case .xLarge: return 18
            }
        }
    }
    
    init(imageUrl: String? = nil, name: String, size: AvatarSize = .medium, isOnline: Bool = false) {
        self.imageUrl = imageUrl
        self.name = name
        self.size = size
        self.isOnline = isOnline
    }
    
    var body: some View {
        ZStack {
            // Avatar content
            if let imageUrl = imageUrl, let url = URL(string: imageUrl) {
                AsyncImage(url: url) { image in
                    image
                        .resizable()
                        .aspectRatio(contentMode: .fill)
                } placeholder: {
                    initialsView
                }
            } else {
                initialsView
            }
            
            // Online indicator
            if isOnline {
                VStack {
                    HStack {
                        Spacer()
                        Circle()
                            .fill(CompoundDesignSystem.Colors.success)
                            .frame(width: 10, height: 10)
                            .overlay(
                                Circle()
                                    .stroke(CompoundDesignSystem.Colors.surface, lineWidth: 2)
                            )
                    }
                    Spacer()
                }
                .padding(CompoundDesignSystem.Spacing.xxxSmall)
            }
        }
        .frame(width: size.dimension, height: size.dimension)
        .background(CompoundDesignSystem.Colors.surfaceVariant)
        .cornerRadius(CompoundDesignSystem.CornerRadius.full)
        .overlay(
            Circle()
                .stroke(CompoundDesignSystem.Colors.neutralVariant, lineWidth: 1)
        )
    }
    
    private var initialsView: some View {
        let initials = nameInitials(from: name)
        return Text(initials)
            .font(.system(size: size.fontSize, weight: .medium))
            .foregroundColor(CompoundDesignSystem.Colors.onSurface)
            .frame(width: size.dimension, height: size.dimension)
            .background(avatarBackgroundColor(for: name))
            .cornerRadius(CompoundDesignSystem.CornerRadius.full)
    }
    
    private func nameInitials(from name: String) -> String {
        let components = name.components(separatedBy: .whitespacesAndNewlines)
        
        if components.count > 1 {
            let first = String(components[0].prefix(1))
            let last = String(components[1].prefix(1))
            return "\(first)\(last)".uppercased()
        } else if let first = name.first {
            return String(first).uppercased()
        }
        
        return "?"
    }
    
    private func avatarBackgroundColor(for name: String) -> Color {
        // Generate a color based on the name hash
        let hash = name.hash
        let colors: [Color] = [
            CompoundDesignSystem.Colors.primary,
            CompoundDesignSystem.Colors.secondary,
            CompoundDesignSystem.Colors.success,
            CompoundDesignSystem.Colors.info,
            CompoundDesignSystem.Colors.warning
        ]
        
        let index = abs(hash) % colors.count
        return colors[index]
    }
}

// MARK: - Preview

#Preview {
    VStack(spacing: CompoundDesignSystem.Spacing.large) {
        // Buttons
        PrimaryButton(title: "Primary Button", icon: "arrow.right") {}
        SecondaryButton(title: "Secondary Button", icon: "arrow.right") {}
        TextButton(title: "Text Button", icon: "arrow.right") {}
        
        HStack(spacing: CompoundDesignSystem.Spacing.medium) {
            IconButton(icon: "heart", size: .small) {}
            IconButton(icon: "heart", size: .medium) {}
            IconButton(icon: "heart", size: .large) {}
        }
        
        // Text Field
        CompoundTextField(placeholder: "Enter your name", icon: "person", text: Binding.constant(""))
        
        // Card
        CompoundCard {
            VStack {
                Text("Card Content")
                    .font(CompoundDesignSystem.Typography.titleMedium())
                Text("This is a card with elevation")
                    .font(CompoundDesignSystem.Typography.bodyMedium())
            }
        }
        
        // Avatars
        HStack(spacing: CompoundDesignSystem.Spacing.medium) {
            CompoundAvatar(name: "John Doe", size: .small)
            CompoundAvatar(name: "Jane Smith", size: .medium, isOnline: true)
            CompoundAvatar(name: "Bob Johnson", size: .large)
        }
    }
    .padding()
}
