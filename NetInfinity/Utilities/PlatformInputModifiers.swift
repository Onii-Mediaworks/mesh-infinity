//
//  PlatformInputModifiers.swift
//  NetInfinity
//

import SwiftUI

#if canImport(UIKit)
import UIKit
#endif

#if canImport(AppKit)
import AppKit
#endif

enum PlatformKeyboardType {
    case `default`
    case emailAddress
    case url
}

enum PlatformAutocapitalization {
    case none
    case words
    case sentences
    case characters
}

enum PlatformTextContentType {
    case emailAddress
    case name
    case newPassword
    case password
    case username
}

extension View {
    @ViewBuilder
    func platformKeyboardType(_ type: PlatformKeyboardType) -> some View {
        #if canImport(UIKit)
        let uiType: UIKeyboardType
        switch type {
        case .default: uiType = .default
        case .emailAddress: uiType = .emailAddress
        case .url: uiType = .URL
        }
        self.keyboardType(uiType)
        #else
        self
        #endif
    }
    
    @ViewBuilder
    func platformAutocapitalization(_ style: PlatformAutocapitalization) -> some View {
        #if canImport(UIKit)
        let uiStyle: TextInputAutocapitalization
        switch style {
        case .none: uiStyle = .never
        case .words: uiStyle = .words
        case .sentences: uiStyle = .sentences
        case .characters: uiStyle = .characters
        }
        self.textInputAutocapitalization(uiStyle)
        #else
        self
        #endif
    }
    
    @ViewBuilder
    func platformAutocorrectionDisabled(_ disabled: Bool) -> some View {
        #if canImport(UIKit)
        self.autocorrectionDisabled(disabled)
        #else
        self
        #endif
    }

    func platformTextContentType(_ type: PlatformTextContentType) -> some View {
        #if canImport(UIKit)
        let contentType: UITextContentType
        switch type {
        case .emailAddress: contentType = .emailAddress
        case .name: contentType = .name
        case .newPassword: contentType = .newPassword
        case .password: contentType = .password
        case .username: contentType = .username
        }
        return AnyView(self.textContentType(contentType))
        #elseif canImport(AppKit)
        if #available(macOS 14.0, *) {
            let contentType: NSTextContentType
            switch type {
            case .emailAddress: contentType = .emailAddress
            case .name: contentType = .name
            case .newPassword: contentType = .newPassword
            case .password: contentType = .password
            case .username: contentType = .username
            }
            return AnyView(self.textContentType(contentType))
        }
        return AnyView(self)
        #else
        return AnyView(self)
        #endif
    }
}
