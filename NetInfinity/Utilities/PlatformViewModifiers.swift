//
//  PlatformViewModifiers.swift
//  NetInfinity
//

import SwiftUI

enum PlatformNavigationBarTitleDisplayMode {
    case automatic
    case inline
    case large
}

extension View {
    @ViewBuilder
    func platformNavigationBarTitleDisplayMode(_ mode: PlatformNavigationBarTitleDisplayMode) -> some View {
        #if os(macOS)
        self
        #else
        let uiMode: NavigationBarItem.TitleDisplayMode
        switch mode {
        case .automatic:
            uiMode = .automatic
        case .inline:
            uiMode = .inline
        case .large:
            uiMode = .large
        }
        self.navigationBarTitleDisplayMode(uiMode)
        #endif
    }
    
    @ViewBuilder
    func platformInsetGroupedListStyle() -> some View {
        #if os(macOS)
        self.listStyle(.inset)
        #else
        self.listStyle(.insetGrouped)
        #endif
    }

    @ViewBuilder
    func platformNavigationBarHidden(_ hidden: Bool) -> some View {
        #if os(macOS)
        self
        #else
        self.navigationBarHidden(hidden)
        #endif
    }
}
