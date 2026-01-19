//
//  ForgotPasswordView.swift
//  NetInfinity
//
//

import SwiftUI

// MARK: - Forgot Password View

struct ForgotPasswordView: View {
    @EnvironmentObject var navigationManager: NavigationManager
    
    @StateObject private var viewModel = ForgotPasswordViewModel()
    @State private var isLoading = false
    @State private var errorMessage: String?
    @State private var showSuccess = false
    
    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                // Header
                headerSection
                
                // Recovery Form
                recoveryForm
                
                // Alternative Options
                alternativeOptionsSection
            }
            .padding()
        }
        .navigationTitle("Forgot Password")
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
        .alert("Password Reset Sent", isPresented: $showSuccess) {
            Button("OK", role: .cancel) {
                navigationManager.navigateToLogin()
            }
        } message: {
            Text("If an account exists for this email, you will receive password reset instructions shortly.")
        }
    }
    
    // MARK: - Subviews
    
    private var headerSection: some View {
        VStack(spacing: 16) {
            Image(systemName: "questionmark.circle")
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(width: 64, height: 64)
                .foregroundColor(.orange)
                .padding(.bottom, 8)
            
            Text("Forgot Password")
                .font(.largeTitle)
                .fontWeight(.bold)
                .multilineTextAlignment(.center)
            
            Text("Enter your email to reset your password")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(.vertical)
    }
    
    private var recoveryForm: some View {
        VStack(spacing: 16) {
            // Email Field
            VStack(alignment: .leading, spacing: 8) {
                Text("Email")
                    .font(.subheadline)
                    .fontWeight(.medium)
                
                TextField("Enter your registered email", text: $viewModel.email)
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
            
            // Reset Password Button
            Button(action: { 
                resetPasswordAction()
            }) {
                Text("Send Reset Instructions")
                    .frame(maxWidth: .infinity)
                    .padding()
            }
            .buttonStyle(.borderedProminent)
            .disabled(!viewModel.isFormValid)
        }
    }
    
    private var alternativeOptionsSection: some View {
        VStack(spacing: 16) {
            Divider()
            
            VStack(spacing: 12) {
                Text("Can't access your email?")
                    .font(.subheadline)
                    .fontWeight(.medium)
                
                Button("Contact Support") { 
                    // Open support contact
                }
                .foregroundColor(.blue)
            }
            
            Divider()
            
            HStack {
                Text("Remember your password?")
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
    }
    
    private var loadingOverlay: some View {
        ZStack {
            Color.black.opacity(0.3)
                .ignoresSafeArea()
            
            VStack(spacing: 16) {
                ProgressView()
                    .progressViewStyle(.circular)
                    .scaleEffect(1.5)
                
                Text("Sending reset instructions...")
                    .font(.headline)
            }
            .padding()
            .background(Color(.systemBackground))
            .cornerRadius(12)
            .shadow(radius: 10)
        }
    }
    
    // MARK: - Actions
    
    private func resetPasswordAction() {
        isLoading = true
        errorMessage = nil
        
        Task {
            do {
                try await viewModel.sendPasswordReset()
                await MainActor.run {
                    isLoading = false
                    showSuccess = true
                }
            } catch let error as AuthenticationError {
                await MainActor.run {
                    isLoading = false
                    errorMessage = error.errorDescription
                }
            } catch {
                await MainActor.run {
                    isLoading = false
                    errorMessage = "An unexpected error occurred"
                }
            }
        }
    }
}

// MARK: - Forgot Password View Model

final class ForgotPasswordViewModel: ObservableObject {
    @Published var email = "" {
        didSet {
            validateForm()
        }
    }
    
    @Published var showEmailError = false
    
    var isFormValid: Bool {
        return !showEmailError && !email.isEmpty
    }
    
    // MARK: - Validation
    
    private func validateForm() {
        showEmailError = email.isEmpty || !email.contains("@") || !email.contains(".")
    }
    
    // MARK: - Password Reset Actions
    
    func sendPasswordReset() async throws {
        validateForm()
        
        guard isFormValid else {
            throw AuthenticationError.invalidCredentials
        }
        
        // Simulate API call
        try await Task.sleep(nanoseconds: 1_500_000_000)
        
        // In a real implementation, this would call the authentication service
        // try await authenticationService.sendPasswordReset(email: email)
    }
}

// MARK: - Preview

#Preview {
    ForgotPasswordView()
        .environmentObject(NavigationManager())
}
