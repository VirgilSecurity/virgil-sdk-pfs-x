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
    fileprivate var mutex = Mutex()
    
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
                return $0.creationDate < $1.creationDate
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
    func getAllSessionsStates() throws -> [(String, SessionState)] {
        Log.debug("Getting all sessions' states")
        
        guard let entry = self.storage.loadValue(forKey: self.getSessionsEntryKey()) as? [String : Any] else {
            return []
        }
        
        var result = [(String, SessionState)]()
        
        for element in entry {
            guard let dict = element.value as? [String : Any] else {
                throw SecureChat.makeError(withCode: .corruptedSavedSession, description: "Corrupted saved session.")
            }
            
            for session in dict {
                guard let state = SessionState(dictionary: session.value) else {
                    throw SecureChat.makeError(withCode: .corruptedSavedSession, description: "Corrupted saved session.")
                }
                
                result.append((element.key, state))
            }
        }
        
        return result
    }
}

extension SessionStorageManager {
    func addSessionState(_ sessionState: SessionState, forRecipientCardId cardId: String) throws {
        Log.debug("Adding session state for: \(cardId). \(sessionState.sessionId)")
        
        self.mutex.lock()
        defer {
            self.mutex.unlock()
        }
        
        var entry = self.storage.loadValue(forKey: self.getSessionsEntryKey()) as? [String : Any] ?? [:]
        
        var recipientEntry = entry[cardId] as? [String : Any] ?? [:]
        
        recipientEntry[sessionState.sessionId.base64EncodedString()] = sessionState.serialize()

        entry[cardId] = recipientEntry
        
        try self.storage.storeValue(entry, forKey: self.getSessionsEntryKey())
    }
}

extension SessionStorageManager {
    func removeSessionsStates(_ array: [(String, Data)]) throws {
        guard !array.isEmpty else {
            return
        }
        
        Log.debug("Removing sessions' states: \(array)")
        
        self.mutex.lock()
        defer {
            self.mutex.unlock()
        }
        
        guard var entry = self.storage.loadValue(forKey: self.getSessionsEntryKey()) as? [String : Any] else {
            throw SecureChat.makeError(withCode: .sessionNotFound, description: "Tried to remove sessions but no sessions found.")
        }
        
        for element in array {
            let cardId = element.0
            let sessionIdStr = element.1.base64EncodedString()
            
            guard var sessions = entry[cardId] as? [String : Any] else {
                throw SecureChat.makeError(withCode: .sessionNotFound, description: "Tried to remove sessions but no sessions for \(cardId) found.")
            }
            
            guard sessions.removeValue(forKey: sessionIdStr) != nil else {
                throw SecureChat.makeError(withCode: .sessionNotFound, description: "Tried to remove sessions but no session for \(sessionIdStr) for this \(cardId) found.")
            }
            
            entry[cardId] = sessions
        }
        
        try self.storage.storeValue(entry, forKey: self.getSessionsEntryKey())
    }
    
    func removeSessionState(forCardId cardId: String, sessionId: Data) throws {
        Log.debug("Removing session state: \(cardId) \(sessionId.base64EncodedString())")
        
        self.mutex.lock()
        defer {
            self.mutex.unlock()
        }
        
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
        return "VIRGIL.SESSIONSV2.OWNER=\(self.cardId)"
    }
}
