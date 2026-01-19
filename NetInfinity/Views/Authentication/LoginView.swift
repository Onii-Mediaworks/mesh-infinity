//
//  LoginView.swift
//  NetInfinity
//
//

import SwiftUI
import Combine

// MARK: - Login View

struct LoginView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var navigationManager: NavigationManager
    @EnvironmentObject var dependencyContainer: AppDependencyContainer
    
    @StateObject private var viewModel: LoginViewModel
    @State private var showPassword = false
    @State private var isLoading = false
    @State private var errorMessage: String?

    init(authenticationService: AuthenticationService) {
        _viewModel = StateObject(wrappedValue: LoginViewModel(authenticationService: authenticationService))
    }
    
    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                // Header
                headerSection
                
                // Login Form
                loginForm
                
                // Footer
                footerSection
            }
            .padding()
        }
        .navigationTitle("Login")
        .platformNavigationBarTitleDisplayMode(.inline)
        .background(Color(.systemBackground))
        .overlay {
            if isLoading {
                loadingOverlay
            }
        }
        .alert("Error", isPresented: Binding(
            get: { errorMessage != nil },
            set: { if !$0 { errorMessage = nil } }
        )) {
            Button("OK", role: .cancel) { }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }
    
    // MARK: - Subviews
    
    private var headerSection: some View {
        VStack(spacing: 16) {
            Image(systemName: "bubble.left.and.bubble.right")
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(width: 64, height: 64)
                .foregroundColor(.blue)
                .padding(.bottom, 8)
            
            Text("Welcome to NetInfinity")
                .font(.largeTitle)
                .fontWeight(.bold)
                .multilineTextAlignment(.center)
            
            Text("Secure messaging for the decentralized web")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(.vertical)
    }
    
    private var loginForm: some View {
        VStack(spacing: 16) {
            // Email Field
            VStack(alignment: .leading, spacing: 8) {
                Text("Email or Username")
                    .font(.subheadline)
                    .fontWeight(.medium)
                
                TextField("Enter your email or username", text: $viewModel.email)
                    .textFieldStyle(.roundedBorder)
                    .platformTextContentType(.emailAddress)
                    .platformKeyboardType(.emailAddress)
                    .platformAutocapitalization(.none)
                    .platformAutocorrectionDisabled(true)
                    .overlay {
                        if viewModel.showEmailError {
                            HStack {
                                Spacer()
                                Image(systemName: "exclamationmark.circle.fill")
                                    .foregroundColor(.red)
                                    .padding(.trailing, 8)
                            }
                        }
                    }
                
                if viewModel.showEmailError {
                    Text("Please enter a valid email or username")
                        .font(.caption)
                        .foregroundColor(.red)
                }
            }
            
            // Password Field
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text("Password")
                        .font(.subheadline)
                        .fontWeight(.medium)
                    
                    Spacer()
                    
                    Button(action: { 
                        showPassword.toggle()
                    }) {
                        Text(showPassword ? "Hide" : "Show")
                            .font(.caption)
                            .foregroundColor(.blue)
                    }
                }
                
                Group {
                    if showPassword {
                        TextField("Enter your password", text: $viewModel.password)
                    } else {
                        SecureField("Enter your password", text: $viewModel.password)
                    }
                }
                .textFieldStyle(.roundedBorder)
                .platformTextContentType(.password)
                .overlay {
                    if viewModel.showPasswordError {
                        HStack {
                            Spacer()
                            Image(systemName: "exclamationmark.circle.fill")
                                .foregroundColor(.red)
                                .padding(.trailing, 8)
                        }
                    }
                }
                
                if viewModel.showPasswordError {
                    Text("Password must be at least 8 characters")
                        .font(.caption)
                        .foregroundColor(.red)
                }
            }
            
            // Forgot Password
            HStack {
                Spacer()
                Button(action: { 
                    navigationManager.navigate(to: .forgotPassword)
                }) {
                    Text("Forgot Password?")
                        .font(.subheadline)
                        .foregroundColor(.blue)
                }
            }
            
            // Login Button
            Button(action: { 
                loginAction()
            }) {
                Text("Login")
                    .frame(maxWidth: .infinity)
                    .padding()
            }
            .buttonStyle(.borderedProminent)
            .disabled(!viewModel.isFormValid)
            
            // Server Selection
            if viewModel.showAdvancedOptions {
                serverSelectionSection
            }
        }
    }
    
    private var serverSelectionSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Homeserver")
                .font(.subheadline)
                .fontWeight(.medium)
            
            TextField("Homeserver URL", text: $viewModel.homeserver)
                .textFieldStyle(.roundedBorder)
                .platformKeyboardType(.url)
                .platformAutocapitalization(.none)
                .platformAutocorrectionDisabled(true)
            
            if viewModel.showHomeserverError {
                Text("Please enter a valid homeserver URL")
                    .font(.caption)
                    .foregroundColor(.red)
            }
        }
    }
    
    private var footerSection: some View {
        VStack(spacing: 16) {
            HStack {
                Text("Don't have an account?")
                    .foregroundColor(.secondary)
                
                Button(action: { 
                    navigationManager.navigate(to: .createAccount)
                }) {
                    Text("Create Account")
                        .fontWeight(.medium)
                        .foregroundColor(.blue)
                }
            }
            
            if viewModel.showAdvancedToggle {
                Button(action: { 
                    withAnimation {
                        viewModel.showAdvancedOptions.toggle()
                    }
                }) {
                    HStack {
                        Text(viewModel.showAdvancedOptions ? "Hide" : "Show")
                        Text("Advanced Options")
                        Image(systemName: viewModel.showAdvancedOptions ? "chevron.up" : "chevron.down")
                    }
                    .font(.subheadline)
                    .foregroundColor(.blue)
                }
            }
        }
    }
    
    private var loadingOverlay: some View {
        ZStack {
            Color.black.opacity(0.3)
                .ignoresSafeArea()
            
            VStack(spacing: 16) {
                ProgressView()
                    .progressViewStyle(.circular)
                    .scaleEffect(1.5)
                
                Text("Logging in...")
                    .font(.headline)
            }
            .padding()
            .background(Color(.systemBackground))
            .cornerRadius(12)
            .shadow(radius: 10)
        }
    }
    
    // MARK: - Actions
    
    private func loginAction() {
        isLoading = true
        errorMessage = nil
        
        Task {
            do {
                let identity = try await dependencyContainer.identityService.loadOrCreateIdentity()
                await MainActor.run {
                    isLoading = false
                    appState.setReady(with: identity)
                    navigationManager.navigateToHome()
                }
            } catch {
                await MainActor.run {
                    isLoading = false
                    errorMessage = "Unable to initialize identity"
                }
            }
        }
    }
}

// MARK: - Login View Model

final class LoginViewModel: ObservableObject {
    @Published var email = "" {
        didSet {
            validateForm()
        }
    }
    
    @Published var password = "" {
        didSet {
            validateForm()
        }
    }
    
    @Published var homeserver = "" {
        didSet {
            validateForm()
        }
    }
    
    @Published var showEmailError = false
    @Published var showPasswordError = false
    @Published var showHomeserverError = false
    @Published var showAdvancedOptions = false
    
    var showAdvancedToggle: Bool {
        // Show advanced toggle only if we detect this might be a developer
        #if DEBUG
        return true
        #else
        return false
        #endif
    }
    
    var isFormValid: Bool {
        return !showEmailError && !showPasswordError && (!showAdvancedOptions || !showHomeserverError)
    }
    
    private let authenticationService: AuthenticationService
    
    init(authenticationService: AuthenticationService) {
        self.authenticationService = authenticationService
    }
    
    // MARK: - Validation
    
    private func validateForm() {
        showEmailError = email.isEmpty || (!email.contains("@") && !email.contains(":"))
        showPasswordError = password.count < 8 && !password.isEmpty
        
        if showAdvancedOptions {
            showHomeserverError = homeserver.isEmpty || !homeserver.hasPrefix("http")
        }
    }
    
    // MARK: - Authentication Actions
    
    func login() async throws -> Session {
        validateForm()
        
        guard isFormValid else {
            throw AuthenticationError.invalidCredentials
        }
        
        return try await authenticationService.login(email: email, password: password)
    }
    
}

// MARK: - Preview

#Preview {
    LoginView(authenticationService: AppDependencyContainer().authenticationService)
        .environmentObject(AppState())
        .environmentObject(NavigationManager())
        .environmentObject(AppDependencyContainer())
}
