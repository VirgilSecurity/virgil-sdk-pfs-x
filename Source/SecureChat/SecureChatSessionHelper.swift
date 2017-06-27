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
    
    func getAllSessions() throws -> [String: SessionState] {
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
    
    func saveSessionState(_ sessionState: SessionState, forRecipientCardId cardId: String) throws {
        guard let userDefaults = UserDefaults(suiteName: self.getSuiteName()) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while creating UserDefaults."])
        }
        
        userDefaults.set(sessionState.serialize(), forKey: self.getSessionName(forCardId: cardId))
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
        
        return state
    }
    
    private static let SecondsInDay: TimeInterval = 24 * 60 * 60
    func removeOldSessions() throws {
        let sessions = try self.getAllSessions()
        
        let date = Date()
        
        var relevantEphKeys: [String] = []
        
        for session in sessions {
            let sessionAge = date.timeIntervalSince1970 - session.value.creationDate.timeIntervalSince1970
//            if (sessionAge > TimeInterval(self.preferences.daysSessionLives) * SecureChat.SecondsInDay) {
//                // FIXME Remove session
//            }
//            else {
//                if let initiatorSession = session.value as? InitiatorSessionState {
//                    relevantEphKeys.append(initiatorSession.ephKeyName)
//                }
//                else if let responderSession = session.value as? ResponderSessionState {
//                    // FIXME
//                }
//            }
        }
    }
}

extension SecureChatSessionHelper {
    static private let DefaultsSuiteName = "VIRGIL.DEFAULTS.%@"
    static private let DefaultsSessionName = "VIRGIL.SESSION.%@"
    
    fileprivate func isSessionName(name: String) -> Bool {
        guard name.characters.count > SecureChatSessionHelper.DefaultsSessionName.characters.count else {
            return false
        }
        
        let index = name.index(name.startIndex, offsetBy: SecureChatSessionHelper.DefaultsSessionName.characters.count)
        let substr = name.substring(to: index)
        
        guard substr == SecureChatSessionHelper.DefaultsSessionName else {
            return false
        }
        
        return true
    }
    
    fileprivate func getSessionName(forCardId cardId: String) -> String {
        return String(format: SecureChatSessionHelper.DefaultsSessionName, cardId)
    }
    
    fileprivate func getSuiteName() -> String {
        return String(format: SecureChatSessionHelper.DefaultsSuiteName, self.cardId)
    }
}
