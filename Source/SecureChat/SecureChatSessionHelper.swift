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
    
    func saveSessionState(_ sessionState: SessionState, forRecipientCardId cardId: String) throws {
        guard let userDefaults = UserDefaults(suiteName: SecureChatSessionHelper.DefaultsSuiteName) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while creating UserDefaults."])
        }
        
        userDefaults.set(sessionState, forKey: cardId)
    }
    
    func getSessionState(forRecipientCardId cardId: String) throws -> SessionState? {
        guard let userDefaults = UserDefaults(suiteName: SecureChatSessionHelper.DefaultsSuiteName) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while creating UserDefaults."])
        }
        
        return userDefaults.value(forKey: cardId) as? SessionState
    }
}
