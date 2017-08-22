//
//  SecureChatSessionHelper.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

class SecureChatSessionHelper {
    fileprivate let cardId: String
    fileprivate let storage: InsensitiveDataStorage
    
    init(cardId: String, storage: InsensitiveDataStorage) {
        self.cardId = cardId
        self.storage = storage
    }
}

extension SecureChatSessionHelper {
    func getSessionState(forRecipientCardId cardId: String) throws -> SessionState? {
        guard let dict = self.storage.loadValue(forKey: cardId) else {
            return nil
        }
        
        guard let state = SessionState(dictionary: dict) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.corruptedSavedSession.rawValue, userInfo: [NSLocalizedDescriptionKey: "Corrupted saved session."])
        }
        
        return state
    }
}

extension SecureChatSessionHelper {
    func getAllSessionsStates() throws -> [String : SessionState] {
        let dict = self.storage.getAllValues() ?? [:]
        
        return try dict.mapPairs({ (key: String, val: Any) -> (String, SessionState) in
            guard let state = SessionState(dictionary: val) else {
                throw SecureChat.makeError(withCode: .corruptedSavedSession, description: "Corrupted saved session.")
            }
            
            return (key, state)
        })
    }
}

extension SecureChatSessionHelper {
    func saveSessionState(_ sessionState: SessionState, forRecipientCardId cardId: String) throws {
        try self.storage.storeValue(sessionState.serialize(), forKey: cardId)
    }
}

extension SecureChatSessionHelper {
    func removeSessionsStates(withNames names: [String]) throws {
        //FIXME: Test names
        try self.storage.removeValues(forKeys: names)
    }
}
