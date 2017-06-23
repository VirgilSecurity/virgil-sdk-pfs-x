//
//  SecureChatSessionHelper.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

class SecureChatSessionHelper {
    static private let DefaultsSuiteName = "VIRGIL.DEFAULTS"
    
    func getAllSessions(crypto: VSSCryptoProtocol) throws -> [String: SessionState] {
        guard let userDefaults = UserDefaults(suiteName: SecureChatSessionHelper.DefaultsSuiteName) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while creating UserDefaults."])
        }
        
        let dict = userDefaults.dictionaryRepresentation()
        
        var res: [String: SessionState] = [:]
        for val in dict {
            guard let state: SessionState = InitiatorSessionState(dictionary: val.value, crypto: crypto) ?? ResponderSessionState(dictionary: val.value, crypto: crypto) else {
                // FIXME
                throw NSError()
            }
            res[val.key] = state
        }
        
        return res
    }
    
    func saveSessionState(_ sessionState: SessionState, forRecipientCardId cardId: String, crypto: VSSCryptoProtocol) throws {
        guard let userDefaults = UserDefaults(suiteName: SecureChatSessionHelper.DefaultsSuiteName) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while creating UserDefaults."])
        }
        
        userDefaults.set(sessionState.serialize(crypto: crypto), forKey: cardId)
    }
    
    func getSessionState(forRecipientCardId cardId: String, crypto: VSSCryptoProtocol) throws -> SessionState? {
        guard let userDefaults = UserDefaults(suiteName: SecureChatSessionHelper.DefaultsSuiteName) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while creating UserDefaults."])
        }
        
        guard let dict = userDefaults.value(forKey: cardId) else {
            return nil
        }
        
        guard let state: SessionState = InitiatorSessionState(dictionary: dict, crypto: crypto) ?? ResponderSessionState(dictionary: dict, crypto: crypto) else {
            // FIXME
            throw NSError()
        }
        
        return state
    }
}
