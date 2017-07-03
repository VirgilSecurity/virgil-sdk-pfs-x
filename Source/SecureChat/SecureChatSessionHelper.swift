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
    
    func saveSessionState(_ sessionState: SessionState, forRecipientCardId cardId: String) throws {
        guard let userDefaults = UserDefaults(suiteName: self.getSuiteName()) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while creating UserDefaults."])
        }
        
        userDefaults.set(sessionState.serialize(), forKey: self.getSessionName(forCardId: cardId))
    }
    
    func removeSessionState(forRecipientCardId cardId: String) throws {
        guard let userDefaults = UserDefaults(suiteName: self.getSuiteName()) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while creating UserDefaults."])
        }
        
        userDefaults.removeObject(forKey: self.getSessionName(forCardId: cardId))
    }
    
    func getSessionState(forRecipientCardId cardId: String) throws -> SessionState? {
        guard let userDefaults = UserDefaults(suiteName: self.getSuiteName()) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while creating UserDefaults."])
        }
        
        guard let dict = userDefaults.value(forKey: self.getSessionName(forCardId: cardId)) else {
            return nil
        }
        
        guard let state: SessionState = InitiatorSessionState(dictionary: dict) ?? ResponderSessionState(dictionary: dict) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Corrupted saved session."])
        }
        
        guard !self.isSessionStateExpired(now: Date(), session: state) else {
            return nil
        }
        
        return state
    }
    
    func removeOldSessions() throws -> (Set<String>, Set<String>, Set<String>) {
        let sessions = try self.getAllSessions()
        
        let date = Date()
        
        var relevantEphKeys = Set<String>()
        var relevantLtCards = Set<String>()
        var relevantOtCards = Set<String>()
        
        for session in sessions {
            if self.isSessionStateExpired(now: date, session: session.value) {
                try self.removeSessionState(forRecipientCardId: session.key)
            }
            else {
                if let initiatorSession = session.value as? InitiatorSessionState {
                    relevantEphKeys.insert(initiatorSession.ephKeyName)
                }
                else if let responderSession = session.value as? ResponderSessionState {
                    relevantLtCards.insert(responderSession.recipientLongTermCardId)
                    relevantOtCards.insert(responderSession.recipientOneTimeCardId)
                }
            }
        }
        
        return (relevantEphKeys, relevantLtCards, relevantOtCards)
    }
    
    private func getAllSessions() throws -> [String: SessionState] {
        guard let userDefaults = UserDefaults(suiteName: self.getSuiteName()) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while creating UserDefaults."])
        }
        
        let dict = userDefaults.dictionaryRepresentation()
        
        var res: [String: SessionState] = [:]
        for val in dict {
            guard self.isSessionName(name: val.key) else {
                continue
            }
            
            guard let state: SessionState = InitiatorSessionState(dictionary: val.value) ?? ResponderSessionState(dictionary: val.value) else {
                throw NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Corrupted saved session."])
            }
            res[val.key] = state
        }
        
        return res
    }
    
    private func isSessionStateExpired(now: Date, session: SessionState) -> Bool {
        return (now > session.expirationDate)
    }
}

extension SecureChatSessionHelper {
    static private let DefaultsSuiteName = "VIRGIL.DEFAULTS.%@"
    static private let DefaultsSessionName = "VIRGIL.SESSION.%@"
    static private let DefaultsSessionNameSearchPattern = "VIRGIL.SESSION."
    
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
