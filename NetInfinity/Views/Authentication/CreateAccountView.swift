//
//  CreateAccountView.swift
//  NetInfinity
//
//

import SwiftUI

// MARK: - Create Account View

struct CreateAccountView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var navigationManager: NavigationManager
    @EnvironmentObject var dependencyContainer: AppDependencyContainer
    
    @StateObject private var viewModel: CreateAccountViewModel
    @State private var showPassword = false
    @State private var showConfirmPassword = false
    @State private var isLoading = false
    @State private var errorMessage: String?
    @State private var showSuccess = false

    init(authenticationService: AuthenticationService) {
        _viewModel = StateObject(wrappedValue: CreateAccountViewModel(authenticationService: authenticationService))
    }
    
    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                // Header
                headerSection
                
                // Registration Form
                registrationForm
                
                // Terms and Privacy
                termsSection
            }
            .padding()
        }
        .navigationTitle("Create Account")
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
        .alert("Account Created", isPresented: $showSuccess) {
            Button("Continue", role: .cancel) {
                navigationManager.navigateToHome()
            }
        } message: {
            Text("Your account has been successfully created!")
        }
    }
    
    // MARK: - Subviews
    
    private var headerSection: some View {
        VStack(spacing: 16) {
            Image(systemName: "person.badge.plus")
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(width: 64, height: 64)
                .foregroundColor(.green)
                .padding(.bottom, 8)
            
            Text("Create Your Account")
                .font(.largeTitle)
                .fontWeight(.bold)
                .multilineTextAlignment(.center)
            
            Text("Join the decentralized communication network")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(.vertical)
    }
    
    private var registrationForm: some View {
        VStack(spacing: 16) {
            // Display Name
            VStack(alignment: .leading, spacing: 8) {
                Text("Display Name")
                    .font(.subheadline)
                    .fontWeight(.medium)
                
                TextField("Enter your display name", text: $viewModel.displayName)
                    .textFieldStyle(.roundedBorder)
                    .platformTextContentType(.name)
                    .overlay {
                        if viewModel.showDisplayNameError {
                            HStack {
                                Spacer()
                                Image(systemName: "exclamationmark.circle.fill")
                                    .foregroundColor(.red)
                                    .padding(.trailing, 8)
                            }
                        }
                    }
                
                if viewModel.showDisplayNameError {
                    Text("Display name must be at least 3 characters")
                        .font(.caption)
                        .foregroundColor(.red)
                }
            }
            
            // Email
            VStack(alignment: .leading, spacing: 8) {
                Text("Email")
                    .font(.subheadline)
                    .fontWeight(.medium)
                
                TextField("Enter your email", text: $viewModel.email)
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
                    Text("Please enter a valid email address")
                        .font(.caption)
                        .foregroundColor(.red)
                }
            }
            
            // Password
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
                        TextField("Create a password", text: $viewModel.password)
                    } else {
                        SecureField("Create a password", text: $viewModel.password)
                    }
                }
                .textFieldStyle(.roundedBorder)
                .platformTextContentType(.newPassword)
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
                    Text("Password must be at least 8 characters with a number and special character")
                        .font(.caption)
                        .foregroundColor(.red)
                }
            }
            
            // Confirm Password
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text("Confirm Password")
                        .font(.subheadline)
                        .fontWeight(.medium)
                    
                    Spacer()
                    
                    Button(action: { 
                        showConfirmPassword.toggle()
                    }) {
                        Text(showConfirmPassword ? "Hide" : "Show")
                            .font(.caption)
                            .foregroundColor(.blue)
                    }
                }
                
                Group {
                    if showConfirmPassword {
                        TextField("Confirm your password", text: $viewModel.confirmPassword)
                    } else {
                        SecureField("Confirm your password", text: $viewModel.confirmPassword)
                    }
                }
                .textFieldStyle(.roundedBorder)
                .platformTextContentType(.newPassword)
                .overlay {
                    if viewModel.showConfirmPasswordError {
                        HStack {
                            Spacer()
                            Image(systemName: "exclamationmark.circle.fill")
                                .foregroundColor(.red)
                                .padding(.trailing, 8)
                        }
                    }
                }
                
                if viewModel.showConfirmPasswordError {
                    Text("Passwords do not match")
                        .font(.caption)
                        .foregroundColor(.red)
                }
            }
            
            // Create Account Button
            Button(action: { 
                createAccountAction()
            }) {
                Text("Create Account")
                    .frame(maxWidth: .infinity)
                    .padding()
            }
            .buttonStyle(.borderedProminent)
            .disabled(!viewModel.isFormValid)
        }
    }
    
    private var termsSection: some View {
        VStack(spacing: 16) {
            Text("By creating an account, you agree to our")
                .font(.footnote)
                .foregroundColor(.secondary)
            
            HStack(spacing: 8) {
                Button("Terms of Service") { }
                    .font(.footnote)
                    .foregroundColor(.blue)
                
                Text("and")
                    .font(.footnote)
                    .foregroundColor(.secondary)
                
                Button("Privacy Policy") { }
                    .font(.footnote)
                    .foregroundColor(.blue)
            }
            
            HStack {
                Text("Already have an account?")
                    .foregroundColor(.secondary)
                
                Button(action: { 
                    navigationManager.navigateToLogin()
                }) {
                    Text("Login")
                        .fontWeight(.medium)
                        .foregroundColor(.blue)
                }
            }
        }
        .font(.footnote)
    }
    
    private var loadingOverlay: some View {
        ZStack {
            Color.black.opacity(0.3)
                .ignoresSafeArea()
            
            VStack(spacing: 16) {
                ProgressView()
                    .progressViewStyle(.circular)
                    .scaleEffect(1.5)
                
                Text("Creating account...")
                    .font(.headline)
            }
            .padding()
            .background(Color(.systemBackground))
            .cornerRadius(12)
            .shadow(radius: 10)
        }
    }
    
    // MARK: - Actions
    
    private func createAccountAction() {
        isLoading = true
        errorMessage = nil
        
        Task {
            do {
                let identity = try await dependencyContainer.identityService.loadOrCreateIdentity()
                await MainActor.run {
                    isLoading = false
                    showSuccess = true
                    appState.setReady(with: identity)
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

// MARK: - Create Account View Model

final class CreateAccountViewModel: ObservableObject {
    @Published var displayName = "" {
        didSet {
            validateForm()
        }
    }
    
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
    
    @Published var confirmPassword = "" {
        didSet {
            validateForm()
        }
    }
    
    @Published var showDisplayNameError = false
    @Published var showEmailError = false
    @Published var showPasswordError = false
    @Published var showConfirmPasswordError = false
    
    var isFormValid: Bool {
        return !showDisplayNameError && !showEmailError && !showPasswordError && !showConfirmPasswordError
    }
    
    private let authenticationService: AuthenticationService
    
    init(authenticationService: AuthenticationService) {
        self.authenticationService = authenticationService
    }
    
    // MARK: - Validation
    
    private func validateForm() {
        showDisplayNameError = displayName.count < 3
        showEmailError = email.isEmpty || !email.contains("@") || !email.contains(".")
        showPasswordError = password.count < 8 || !password.contains(where: { $0.isNumber }) || !password.contains(where: { !$0.isLetter && !$0.isNumber })
        showConfirmPasswordError = confirmPassword != password && !confirmPassword.isEmpty
    }
    
    // MARK: - Authentication Actions
    
    func createAccount() async throws -> Session {
        validateForm()
        
        guard isFormValid else {
            throw AuthenticationError.registrationFailed
        }
        
        return try await authenticationService.register(
            email: email,
            password: password,
            displayName: displayName
        )
    }
}

// MARK: - Preview

#Preview {
    CreateAccountView(authenticationService: AppDependencyContainer().authenticationService)
        .environmentObject(AppState())
        .environmentObject(NavigationManager())
        .environmentObject(AppDependencyContainer())
}
