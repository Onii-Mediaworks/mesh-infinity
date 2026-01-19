//
//  TrustService.swift
//  NetInfinity
//

import Foundation

// MARK: - Trust Models

enum TrustLevel: Int, CaseIterable, Identifiable, Codable, Comparable {
    case untrusted = 0
    case caution = 1
    case trusted = 2
    case highlyTrusted = 3

    var id: Int { rawValue }

    var title: String {
        switch self {
        case .untrusted: return "Untrusted"
        case .caution: return "Caution"
        case .trusted: return "Trusted"
        case .highlyTrusted: return "Highly Trusted"
        }
    }

    static func < (lhs: TrustLevel, rhs: TrustLevel) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

enum VerificationMethod: String, CaseIterable, Identifiable, Codable {
    case inPerson
    case sharedSecret
    case trustedIntroduction
    case pki

    var id: String { rawValue }

    var title: String {
        switch self {
        case .inPerson: return "In Person"
        case .sharedSecret: return "Shared Secret"
        case .trustedIntroduction: return "Trusted Introduction"
        case .pki: return "PKI"
        }
    }

    var defaultTrust: TrustLevel {
        switch self {
        case .inPerson, .sharedSecret:
            return .trusted
        case .trustedIntroduction:
            return .caution
        case .pki:
            return .highlyTrusted
        }
    }
}

struct TrustEndorsement: Identifiable, Codable, Equatable {
    let id: String
    let endorserId: String
    let trustLevel: TrustLevel
    let createdAt: Date

    init(endorserId: String, trustLevel: TrustLevel, createdAt: Date = Date()) {
        self.id = UUID().uuidString
        self.endorserId = endorserId
        self.trustLevel = trustLevel
        self.createdAt = createdAt
    }
}

struct PeerIdentity: Identifiable, Codable, Equatable {
    let id: String
    var displayName: String
    var publicKeyFingerprint: String
    var trustLevel: TrustLevel
    var verificationMethods: [VerificationMethod]
    var endorsements: [TrustEndorsement]
    var lastSeen: Date
}

// MARK: - Trust Service

protocol TrustService {
    func pairingCode(for identity: LocalIdentity?) -> String
    func listPeers() async throws -> [PeerIdentity]
    func addPeer(pairingCode: String, verificationMethod: VerificationMethod) async throws -> PeerIdentity
    func updateTrustLevel(peerId: String, trustLevel: TrustLevel) async throws -> PeerIdentity
    func endorsePeer(peerId: String, by endorserId: String, trustLevel: TrustLevel) async throws -> PeerIdentity
    func removePeer(peerId: String) async throws
}

enum TrustServiceError: Error, LocalizedError {
    case invalidPairingCode
    case peerNotFound

    var errorDescription: String? {
        switch self {
        case .invalidPairingCode:
            return "Invalid pairing code"
        case .peerNotFound:
            return "Peer not found"
        }
    }
}

final class DefaultTrustService: TrustService {
    private let storageService: StorageService
    private let storageKey = "trust.peers"

    init(storageService: StorageService) {
        self.storageService = storageService
    }

    func pairingCode(for identity: LocalIdentity?) -> String {
        guard let identity else {
            return "Generating..."
        }
        return formatPairingCode(identity.id)
    }

    func listPeers() async throws -> [PeerIdentity] {
        try await loadPeers()
    }

    func addPeer(pairingCode: String, verificationMethod: VerificationMethod) async throws -> PeerIdentity {
        let normalized = normalizePairingCode(pairingCode)
        guard !normalized.isEmpty else {
            throw TrustServiceError.invalidPairingCode
        }

        var peers = try await loadPeers()
        let peerId = String(normalized.prefix(12)).lowercased()

        if let index = peers.firstIndex(where: { $0.id == peerId }) {
            peers[index].verificationMethods = mergeMethods(
                peers[index].verificationMethods,
                adding: verificationMethod
            )
            peers[index].trustLevel = max(peers[index].trustLevel, verificationMethod.defaultTrust)
            peers[index].lastSeen = Date()
            try await savePeers(peers)
            return peers[index]
        }

        let peer = PeerIdentity(
            id: peerId,
            displayName: "Peer \(peerId.prefix(6).uppercased())",
            publicKeyFingerprint: normalized.lowercased(),
            trustLevel: verificationMethod.defaultTrust,
            verificationMethods: [verificationMethod],
            endorsements: [],
            lastSeen: Date()
        )

        peers.append(peer)
        try await savePeers(peers)
        return peer
    }

    func updateTrustLevel(peerId: String, trustLevel: TrustLevel) async throws -> PeerIdentity {
        var peers = try await loadPeers()
        guard let index = peers.firstIndex(where: { $0.id == peerId }) else {
            throw TrustServiceError.peerNotFound
        }
        peers[index].trustLevel = trustLevel
        peers[index].lastSeen = Date()
        try await savePeers(peers)
        return peers[index]
    }

    func endorsePeer(peerId: String, by endorserId: String, trustLevel: TrustLevel) async throws -> PeerIdentity {
        var peers = try await loadPeers()
        guard let index = peers.firstIndex(where: { $0.id == peerId }) else {
            throw TrustServiceError.peerNotFound
        }
        let endorsement = TrustEndorsement(endorserId: endorserId, trustLevel: trustLevel)
        peers[index].endorsements.append(endorsement)
        peers[index].trustLevel = max(peers[index].trustLevel, trustLevel)
        peers[index].lastSeen = Date()
        try await savePeers(peers)
        return peers[index]
    }

    func removePeer(peerId: String) async throws {
        var peers = try await loadPeers()
        peers.removeAll { $0.id == peerId }
        try await savePeers(peers)
    }

    // MARK: - Storage Helpers

    private func loadPeers() async throws -> [PeerIdentity] {
        if let peers: [PeerIdentity] = try await storageService.get(storageKey) {
            return peers
        }
        return []
    }

    private func savePeers(_ peers: [PeerIdentity]) async throws {
        try await storageService.set(storageKey, value: peers)
    }

    private func mergeMethods(_ existing: [VerificationMethod], adding method: VerificationMethod) -> [VerificationMethod] {
        if existing.contains(method) {
            return existing
        }
        return existing + [method]
    }

    private func normalizePairingCode(_ code: String) -> String {
        let trimmed = code
            .uppercased()
            .replacingOccurrences(of: "NI1", with: "")
            .replacingOccurrences(of: "-", with: "")
            .replacingOccurrences(of: " ", with: "")

        return String(trimmed.filter { isHexCharacter($0) })
    }

    private func isHexCharacter(_ char: Character) -> Bool {
        switch char {
        case "0"..."9", "A"..."F":
            return true
        default:
            return false
        }
    }

    private func formatPairingCode(_ fingerprint: String) -> String {
        let clean = fingerprint.uppercased().filter { isHexCharacter($0) }
        let short = String(clean.prefix(20))
        let grouped = stride(from: 0, to: short.count, by: 4).map { index -> String in
            let start = short.index(short.startIndex, offsetBy: index)
            let end = short.index(start, offsetBy: min(4, short.count - index))
            return String(short[start..<end])
        }
        return "NI1-" + grouped.joined(separator: "-")
    }
}
