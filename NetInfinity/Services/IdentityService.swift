//
//  IdentityService.swift
//  NetInfinity
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

protocol IdentityService {
    func loadOrCreateIdentity() async throws -> LocalIdentity
    func getIdentity() async throws -> LocalIdentity?
    func resetIdentity() async throws -> LocalIdentity
}

struct LocalIdentity: Codable, Equatable, Identifiable {
    let id: String
    let publicKey: String
    let privateKey: String
    let createdAt: Date
}

final class DefaultIdentityService: IdentityService {
    private let storageService: StorageService
    private let keychainService: KeychainService
    private let metadataKey = "identity.local.metadata"
    private let privateKeyKey = "identity.local.privateKey"
    
    init(storageService: StorageService, keychainService: KeychainService) {
        self.storageService = storageService
        self.keychainService = keychainService
    }
    
    func getIdentity() async throws -> LocalIdentity? {
        if let identity = try await loadIdentityFromStorage() {
            return identity
        }
        return try await loadIdentityFromKeychainOnly()
    }
    
    func loadOrCreateIdentity() async throws -> LocalIdentity {
        if let identity = try await getIdentity() {
            return identity
        }
        return try await createAndStoreIdentity()
    }
    
    func resetIdentity() async throws -> LocalIdentity {
        try keychainService.deleteData(for: privateKeyKey)
        try storageService.remove(metadataKey)
        return try await createAndStoreIdentity()
    }
    
    private func loadIdentityFromStorage() async throws -> LocalIdentity? {
        guard let metadata: LocalIdentityMetadata = try await storageService.get(metadataKey) else {
            return nil
        }
        guard let privateKeyData = try keychainService.getData(for: privateKeyKey) else {
            try? storageService.remove(metadataKey)
            return nil
        }
        return LocalIdentity(
            id: metadata.id,
            publicKey: metadata.publicKey,
            privateKey: privateKeyData.base64EncodedString(),
            createdAt: metadata.createdAt
        )
    }
    
    private func loadIdentityFromKeychainOnly() async throws -> LocalIdentity? {
#if canImport(CryptoKit)
        guard let privateKeyData = try keychainService.getData(for: privateKeyKey) else {
            return nil
        }
        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData)
        let publicKeyData = privateKey.publicKey.rawRepresentation
        let metadata = LocalIdentityMetadata(
            id: Self.fingerprint(for: publicKeyData),
            publicKey: publicKeyData.base64EncodedString(),
            createdAt: Date()
        )
        try await storageService.set(metadataKey, value: metadata)
        return LocalIdentity(
            id: metadata.id,
            publicKey: metadata.publicKey,
            privateKey: privateKeyData.base64EncodedString(),
            createdAt: metadata.createdAt
        )
#else
        return nil
#endif
    }
    
    private func createAndStoreIdentity() async throws -> LocalIdentity {
#if canImport(CryptoKit)
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let publicKeyData = publicKey.rawRepresentation
        let privateKeyData = privateKey.rawRepresentation
        let id = Self.fingerprint(for: publicKeyData)
        let metadata = LocalIdentityMetadata(
            id: id,
            publicKey: publicKeyData.base64EncodedString(),
            createdAt: Date()
        )
        try keychainService.setData(privateKeyData, for: privateKeyKey)
        try await storageService.set(metadataKey, value: metadata)
        return LocalIdentity(
            id: metadata.id,
            publicKey: metadata.publicKey,
            privateKey: privateKeyData.base64EncodedString(),
            createdAt: metadata.createdAt
        )
#else
        throw AppError.unknownError
#endif
    }
    
#if canImport(CryptoKit)
    private static func fingerprint(for data: Data) -> String {
        let hash = SHA256.hash(data: data)
        return hash.map { String(format: "%02x", $0) }.joined()
    }
#endif
}

private struct LocalIdentityMetadata: Codable {
    let id: String
    let publicKey: String
    let createdAt: Date
}
