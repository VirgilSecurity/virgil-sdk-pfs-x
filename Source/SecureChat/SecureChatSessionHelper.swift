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
    
    init(cardId: String) {
        self.cardId = cardId
    }
}

extension SecureChatSessionHelper {
    func getSessionState(forRecipientCardId cardId: String) throws -> SessionState? {
        guard let userDefaults = UserDefaults(suiteName: self.getSuiteName()) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.creatingUserDefaults.rawValue, userInfo: [NSLocalizedDescriptionKey: "Error while creating UserDefaults."])
        }
        
        guard let dict = userDefaults.value(forKey: self.getSessionName(forCardId: cardId)) else {
            return nil
        }
        
        guard let state: SessionState = InitiatorSessionState(dictionary: dict) ?? ResponderSessionState(dictionary: dict) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.corruptedSavedSession.rawValue, userInfo: [NSLocalizedDescriptionKey: "Corrupted saved session."])
        }
        
        return state
    }
}

extension SecureChatSessionHelper {
    func getAllSessionsStates() throws -> [String: SessionState] {
        guard let userDefaults = UserDefaults(suiteName: self.getSuiteName()) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.creatingUserDefaults.rawValue, userInfo: [NSLocalizedDescriptionKey: "Error while creating UserDefaults."])
        }
        
        return try self.getAllSessionsStates(userDefaults: userDefaults)
    }
    
    private func getAllSessionsStates(userDefaults: UserDefaults) throws -> [String: SessionState] {
        let dict = userDefaults.dictionaryRepresentation()
        
        var res: [String: SessionState] = [:]
        for val in dict {
            guard self.isSessionName(name: val.key) else {
                continue
            }
            
            guard let state: SessionState = InitiatorSessionState(dictionary: val.value) ?? ResponderSessionState(dictionary: val.value) else {
                throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.corruptedSavedSession.rawValue, userInfo: [NSLocalizedDescriptionKey: "Corrupted saved session."])
            }
            res[val.key] = state
        }
        
        return res
    }
}

extension SecureChatSessionHelper {
    func saveSessionState(_ sessionState: SessionState, forRecipientCardId cardId: String, synchronize: Bool = true) throws {
        guard let userDefaults = UserDefaults(suiteName: self.getSuiteName()) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.creatingUserDefaults.rawValue, userInfo: [NSLocalizedDescriptionKey: "Error while creating UserDefaults."])
        }
        
        self.saveSessionState(sessionState, forRecipientCardId: cardId, userDefaults: userDefaults, synchronize: synchronize)
    }
    
    private func saveSessionState(_ sessionState: SessionState, forRecipientCardId cardId: String, userDefaults: UserDefaults, synchronize: Bool) {
        userDefaults.set(sessionState.serialize(), forKey: self.getSessionName(forCardId: cardId))
        
        if synchronize {
            userDefaults.synchronize()
        }
    }
}

extension SecureChatSessionHelper {
    func removeSessionsStates(withNames names: [String]) throws {
        guard let userDefaults = UserDefaults(suiteName: self.getSuiteName()) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.creatingUserDefaults.rawValue, userInfo: [NSLocalizedDescriptionKey: "Error while creating UserDefaults."])
        }
        
        for name in names {
            self.removeSessionState(withName: name, userDefaults: userDefaults, synchronize: false)
        }
        
        userDefaults.synchronize()
    }
    
    func removeSessionsStates(withCardsIds cardsIds: [String]) throws {
        try self.removeSessionsStates(withNames: cardsIds.map({ self.getSessionName(forCardId: $0) }))
    }
    
    private func removeSessionState(withName name: String, userDefaults: UserDefaults, synchronize: Bool) {
        userDefaults.removeObject(forKey: name)
        
        if synchronize {
            userDefaults.synchronize()
        }
    }
}

extension SecureChatSessionHelper {
    static private let DefaultsSuiteName = "VIRGIL.DEFAULTS.%@"
    static private let DefaultsSessionName = "VIRGIL.SESSION.%@"
    static private let DefaultsSessionNameSearchPattern = "VIRGIL.SESSION."
    
    func getCardId(fromSessionName name: String) -> String? {
        guard let prefixRange = name.range(of: SecureChatSessionHelper.DefaultsSessionNameSearchPattern) else {
            return nil
        }
        
        var cardId = name
        cardId.removeSubrange(prefixRange)
        
        return cardId
    }
    
    fileprivate func isSessionName(name: String) -> Bool {
        return name.range(of: SecureChatSessionHelper.DefaultsSessionNameSearchPattern) != nil
    }
    
    fileprivate func getSessionName(forCardId cardId: String) -> String {
        return String(format: SecureChatSessionHelper.DefaultsSessionName, cardId)
    }
    
    fileprivate func getSuiteName() -> String {
        return String(format: SecureChatSessionHelper.DefaultsSuiteName, self.cardId)
    }
}
