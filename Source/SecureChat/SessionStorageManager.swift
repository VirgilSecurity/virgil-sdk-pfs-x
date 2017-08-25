//
//  SessionStorageManager.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

class SessionStorageManager {
    fileprivate let cardId: String
    fileprivate let storage: InsensitiveDataStorage
    
    init(cardId: String, storage: InsensitiveDataStorage) {
        self.cardId = cardId
        self.storage = storage
    }
}

extension SessionStorageManager {
    func getNewestSessionState(forRecipientCardId cardId: String) throws -> SessionState? {
        Log.debug("Getting newest session state for: \(cardId)")
        
        guard let entry = self.storage.loadValue(forKey: self.getSessionsEntryKey()) as? [String : Any],
            let sessionsDict = entry[cardId] as? [String : Any] else {
                return nil
        }
        
        return try sessionsDict
            .map({ (sessionIdStr: String, dict: Any) throws -> SessionState in
                guard let state = SessionState(dictionary: dict) else {
                    throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.corruptedSavedSession.rawValue, userInfo: [NSLocalizedDescriptionKey: "Corrupted saved session."])
                }
                
                return state
            })
            .max(by: {
                return $0.0.creationDate < $0.1.creationDate
            })
    }
    
    func getSessionState(forRecipientCardId cardId: String, sessionId: Data) throws -> SessionState? {
        Log.debug("Getting session state for: \(cardId), sessionId: \(sessionId.base64EncodedString())")
        
        guard let entry = self.storage.loadValue(forKey: self.getSessionsEntryKey()) as? [String : Any],
            let sessionsDict = entry[cardId] as? [String : Any],
            let sessionDict = sessionsDict[sessionId.base64EncodedString()] else {
                return nil
        }
        
        guard let state = SessionState(dictionary: sessionDict) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.corruptedSavedSession.rawValue, userInfo: [NSLocalizedDescriptionKey: "Corrupted saved session."])
        }
        
        return state
    }
    
    func getSessionStatesIds(forRecipientCardId cardId: String) throws -> [Data] {
        Log.debug("Getting session states for: \(cardId)")
        
        guard let entry = self.storage.loadValue(forKey: self.getSessionsEntryKey()) as? [String : Any],
            let sessionsDict = entry[cardId] as? [String : Any] else {
                return []
        }
        
        return try sessionsDict
            .keys
            .map({
                guard let sessionId = Data(base64Encoded: $0) else {
                    throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.corruptedSavedSession.rawValue, userInfo: [NSLocalizedDescriptionKey: "Corrupted saved session."])
                }
                
                return sessionId
            })
    }
}

extension SessionStorageManager {
    func getAllSessionsStates() throws -> [String : [Data : SessionState]] {
        Log.debug("Getting all sessions' states")
        
        guard let entry = self.storage.loadValue(forKey: self.getSessionsEntryKey()) as? [String : Any] else {
            return [:]
        }
        
        return try entry.mapPairs({ (key: String, val: Any) -> (String, [Data : SessionState]) in
            guard let dict = val as? [String : Any] else {
                throw SecureChat.makeError(withCode: .corruptedSavedSession, description: "Corrupted saved session.")
            }
            
            var sessions = [Data : SessionState]()
            for session in dict {
                guard let sessionId = Data(base64Encoded: session.key),
                    let state = SessionState(dictionary: session.value) else {
                        throw SecureChat.makeError(withCode: .corruptedSavedSession, description: "Corrupted saved session.")
                }
                
                sessions[sessionId] = state
            }
            
            
            return (key, sessions)
        })
    }
}

extension SessionStorageManager {
    func addSessionState(_ sessionState: SessionState, forRecipientCardId cardId: String) throws {
        Log.debug("Adding session state for: \(cardId). \(sessionState.sessionId)")
        
        var entry = self.storage.loadValue(forKey: self.getSessionsEntryKey()) as? [String : Any] ?? [:]
        
        var recipientEntry = entry[cardId] as? [String : Any] ?? [:]
        
        recipientEntry[sessionState.sessionId.base64EncodedString()] = sessionState.serialize()

        entry[cardId] = recipientEntry
        
        try self.storage.storeValue(entry, forKey: self.getSessionsEntryKey())
    }
}

extension SessionStorageManager {
    func removeSessionsStates(dict: [String: [Data]?]) throws {
        Log.debug("Removing sessions' states: \(dict)")
        
        guard !dict.isEmpty else {
            return
        }
        
        guard var entry = self.storage.loadValue(forKey: self.getSessionsEntryKey()) as? [String : Any] else {
            throw SecureChat.makeError(withCode: .sessionNotFound, description: "Tried to remove sessions but no sessions found.")
        }
        
        for d in dict {
            guard var sessions = entry[d.key] as? [String : Any] else {
                throw SecureChat.makeError(withCode: .sessionNotFound, description: "Tried to remove sessions but no sessions for \(d.key) found.")
            }
            
            if let sessionIds = d.value {
                for sessionId in sessionIds {
                    guard sessions.removeValue(forKey: sessionId.base64EncodedString()) != nil else {
                        throw SecureChat.makeError(withCode: .sessionNotFound, description: "Tried to remove sessions but no session for \(sessionId.base64EncodedString()) for this \(cardId) found.")
                    }
                }
                
                entry[d.key] = sessions
            }
            else {
                entry.removeValue(forKey: d.key)
            }
        }
        
        try self.storage.storeValue(entry, forKey: self.getSessionsEntryKey())
    }
    
    func removeSessionState(forCardId cardId: String, sessionId: Data) throws {
        Log.debug("Removing session state: \(cardId) \(sessionId.base64EncodedString())")
        
        guard var entry = self.storage.loadValue(forKey: self.getSessionsEntryKey()) as? [String : Any] else {
            throw SecureChat.makeError(withCode: .sessionNotFound, description: "Tried to remove sessions but no sessions found.")
        }
        
        guard var sessions = entry[cardId] as? [String : Any] else {
            throw SecureChat.makeError(withCode: .sessionNotFound, description: "Tried to remove sessions but no sessions for \(cardId) found.")
        }
        
        guard sessions.removeValue(forKey: sessionId.base64EncodedString()) != nil else {
            throw SecureChat.makeError(withCode: .sessionNotFound, description: "Tried to remove sessions but no session for \(sessionId.base64EncodedString()) for \(cardId) found.")
        }
        
        entry[cardId] = sessions
        
        try self.storage.storeValue(entry, forKey: self.getSessionsEntryKey())
    }
}

extension SessionStorageManager {
    fileprivate func getSessionsEntryKey() -> String {
        return "VIRGIL.SESSIONS.OWNER=\(self.cardId)"
    }
}
