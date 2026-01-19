//
//  CallView.swift
//  NetInfinity
//

import SwiftUI

// MARK: - Call View

struct CallView: View {
    let callId: String
    
    @Environment(\.dismiss) private var dismiss
    @State private var isMuted = false
    @State private var isSpeakerOn = false
    
    var body: some View {
        VStack(spacing: 32) {
            VStack(spacing: 8) {
                Text("Secure Call")
                    .font(.title2)
                    .fontWeight(.semibold)
                Text("Call ID: \(callId)")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            
            Circle()
                .fill(Color.blue.opacity(0.2))
                .frame(width: 140, height: 140)
                .overlay {
                    Image(systemName: "phone.fill")
                        .font(.largeTitle)
                        .foregroundColor(.blue)
                }
            
            HStack(spacing: 20) {
                controlButton(icon: "mic.slash.fill", label: "Mute", isActive: isMuted) {
                    isMuted.toggle()
                }
                controlButton(icon: "speaker.wave.2.fill", label: "Speaker", isActive: isSpeakerOn) {
                    isSpeakerOn.toggle()
                }
                controlButton(icon: "phone.down.fill", label: "End", isActive: true, tint: .red) {
                    dismiss()
                }
            }
        }
        .padding(.top, 40)
        .navigationTitle("Call")
        .platformNavigationBarTitleDisplayMode(.inline)
    }
    
    private func controlButton(icon: String, label: String, isActive: Bool, tint: Color = .blue, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.title2)
                    .foregroundColor(.white)
                    .frame(width: 56, height: 56)
                    .background(isActive ? tint : Color.gray)
                    .clipShape(Circle())
                Text(label)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
    }
}

#Preview {
    CallView(callId: "call-123")
}
