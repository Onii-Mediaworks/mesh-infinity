//
//  KeychainService.swift
//  NetInfinity
//

import Foundation
import Security

protocol KeychainService {
    func getData(for key: String) throws -> Data?
    func setData(_ data: Data, for key: String) throws
    func deleteData(for key: String) throws
}

enum KeychainError: Error {
    case unhandledStatus(OSStatus)
}

final class DefaultKeychainService: KeychainService {
    private let service: String
    
    init(service: String = "NetInfinity") {
        self.service = service
    }
    
    func getData(for key: String) throws -> Data? {
        var query = baseQuery(for: key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            return result as? Data
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainError.unhandledStatus(status)
        }
    }
    
    func setData(_ data: Data, for key: String) throws {
        var query = baseQuery(for: key)
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        
        switch status {
        case errSecSuccess:
            let attributes: [String: Any] = [kSecValueData as String: data]
            let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
            if updateStatus != errSecSuccess {
                throw KeychainError.unhandledStatus(updateStatus)
            }
        case errSecItemNotFound:
            query[kSecValueData as String] = data
            query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
            let addStatus = SecItemAdd(query as CFDictionary, nil)
            if addStatus != errSecSuccess {
                throw KeychainError.unhandledStatus(addStatus)
            }
        default:
            throw KeychainError.unhandledStatus(status)
        }
    }
    
    func deleteData(for key: String) throws {
        let status = SecItemDelete(baseQuery(for: key) as CFDictionary)
        switch status {
        case errSecSuccess, errSecItemNotFound:
            return
        default:
            throw KeychainError.unhandledStatus(status)
        }
    }
    
    private func baseQuery(for key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
    }
}
