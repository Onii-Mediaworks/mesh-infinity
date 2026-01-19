//
//  NodeMode.swift
//  NetInfinity
//

import Foundation

enum NodeMode: String, CaseIterable, Identifiable, Codable {
    case client
    case server
    case dual
    
    var id: String { rawValue }
    
    var title: String {
        switch self {
        case .client: return "Client"
        case .server: return "Server"
        case .dual: return "Dual"
        }
    }
    
    var description: String {
        switch self {
        case .client:
            return "Chat and mesh networking only."
        case .server:
            return "Headless server node for storage and routing."
        case .dual:
            return "Client plus a server node running separately."
        }
    }
    
    var includesClient: Bool {
        switch self {
        case .client, .dual: return true
        case .server: return false
        }
    }
    
    var includesServer: Bool {
        switch self {
        case .server, .dual: return true
        case .client: return false
        }
    }
}
