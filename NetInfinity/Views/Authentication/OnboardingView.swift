//
//  OnboardingView.swift
//  NetInfinity
//
//

import SwiftUI

// MARK: - Onboarding View

struct OnboardingView: View {
    @EnvironmentObject var navigationManager: NavigationManager
    
    @State private var currentPage = 0
    private let features = [
        OnboardingFeature(
            title: "Secure Messaging",
            description: "End-to-end encrypted conversations that protect your privacy",
            icon: "lock.shield",
            color: .blue
        ),
        OnboardingFeature(
            title: "Decentralized Network",
            description: "No single point of control - your data, your rules",
            icon: "network",
            color: .green
        ),
        OnboardingFeature(
            title: "Cross-Platform",
            description: "Seamless experience across all your devices",
            icon: "iphone.and.arrow.forward",
            color: .purple
        ),
        OnboardingFeature(
            title: "Open Source",
            description: "Transparent code you can trust and verify",
            icon: "chevron.left.forwardslash.chevron.right",
            color: .orange
        )
    ]
    
    var body: some View {
        VStack {
            // Skip button
            HStack {
                Spacer()
                Button("Skip") {
                    navigationManager.navigateToHome()
                }
                .foregroundColor(.blue)
                .padding()
            }
            
            // Onboarding content
            Group {
                #if os(macOS)
                TabView(selection: $currentPage) {
                    ForEach(0..<features.count, id: \.self) { index in
                        featureView(for: features[index])
                            .tag(index)
                    }
                }
                #else
                TabView(selection: $currentPage) {
                    ForEach(0..<features.count, id: \.self) { index in
                        featureView(for: features[index])
                            .tag(index)
                    }
                }
                .tabViewStyle(.page(indexDisplayMode: .never))
                .indexViewStyle(.page(backgroundDisplayMode: .always))
                #endif
            }
            
            // Page indicator
            HStack(spacing: 8) {
                ForEach(0..<features.count, id: \.self) { index in
                    Circle()
                        .frame(width: 8, height: 8)
                        .foregroundColor(currentPage == index ? .blue : .gray)
                        .animation(.easeInOut, value: currentPage)
                }
            }
            .padding(.bottom, 24)
            
            // Action buttons
            VStack(spacing: 16) {
                Button(action: {
                    if currentPage < features.count - 1 {
                        withAnimation {
                            currentPage += 1
                        }
                    } else {
                        navigationManager.navigateToHome()
                    }
                }) {
                    if currentPage < features.count - 1 {
                        Text("Next")
                            .frame(maxWidth: .infinity)
                    } else {
                        Text("Continue")
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .padding(.horizontal)
            }
            .padding(.bottom, 32)
        }
        .navigationTitle("Welcome")
        .platformNavigationBarTitleDisplayMode(.inline)
    }
    
    private func featureView(for feature: OnboardingFeature) -> some View {
        VStack(spacing: 32) {
            Image(systemName: feature.icon)
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(width: 100, height: 100)
                .foregroundColor(feature.color)
                .padding()
                .background(feature.color.opacity(0.1))
                .cornerRadius(20)
            
            VStack(spacing: 16) {
                Text(feature.title)
                    .font(.title)
                    .fontWeight(.bold)
                
                Text(feature.description)
                    .font(.body)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }
        }
        .padding()
    }
}

// MARK: - Onboarding Feature Model

struct OnboardingFeature: Identifiable {
    let id = UUID()
    let title: String
    let description: String
    let icon: String
    let color: Color
}

// MARK: - Preview

#Preview {
    OnboardingView()
        .environmentObject(NavigationManager())
}
