//
//  PlatformColor.swift
//  NetInfinity
//

import SwiftUI

#if os(macOS)
import AppKit

extension NSColor {
    static var systemBackground: NSColor { windowBackgroundColor }
    static var secondarySystemBackground: NSColor { controlBackgroundColor }
    static var systemGray6: NSColor { controlBackgroundColor }
    static var systemGray5: NSColor { systemGray }
    static var systemGray4: NSColor { systemGray }
    static var systemBlue: NSColor { controlAccentColor }
    static var systemGreen: NSColor { green }
}

extension Color {
    init(_ color: NSColor) {
        self.init(nsColor: color)
    }
}
#endif
