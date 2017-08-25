//
//  SecureChat.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/20/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

@objc(VSPSecureChat) public class SecureChat: NSObject {
    public static let ErrorDomain = "VSPSecureChatErrorDomain"
    
    public let preferences: SecureChatPreferences
    public let client: Client
    
    fileprivate let keyHelper: SecureChatKeyHelper
    fileprivate let cardsHelper: SecureChatCardsHelper
    fileprivate let sessionHelper: SecureChatSessionHelper
    fileprivate let exhaustHelper: SecureChatExhaustHelper
    fileprivate let sessionInitializer: SessionInitializer
    fileprivate let rotator: KeysRotator
    
    public init(preferences: SecureChatPreferences) {
        self.preferences = preferences
        self.client = Client(serviceConfig: self.preferences.serviceConfig)
        
        self.keyHelper = SecureChatKeyHelper(crypto: self.preferences.crypto, keyStorage: self.preferences.keyStorage, identityCardId: self.preferences.identityCard.identifier, longTermKeyTtl: self.preferences.longTermKeysTtl)
        self.cardsHelper = SecureChatCardsHelper(crypto: self.preferences.crypto, myPrivateKey: self.preferences.privateKey, client: self.client, deviceManager: self.preferences.deviceManager, keyHelper: self.keyHelper)
        
        self.sessionHelper = SecureChatSessionHelper(cardId: self.preferences.identityCard.identifier, storage: self.preferences.insensitiveDataStorage)
        
        self.exhaustHelper = SecureChatExhaustHelper(cardId: self.preferences.identityCard.identifier, storage: self.preferences.insensitiveDataStorage)
        
        self.sessionInitializer = SessionInitializer(crypto: self.preferences.crypto, identityPrivateKey: self.preferences.privateKey, identityCard: self.preferences.identityCard, sessionHelper: self.sessionHelper, keyHelper: self.keyHelper)
        
        self.rotator = KeysRotator(cardsHelper: self.cardsHelper, sessionHelper: self.sessionHelper, keyHelper: self.keyHelper, exhaustHelper: self.exhaustHelper, preferences: self.preferences, client: self.client)
        
        super.init()
    }
    
    class func makeError(withCode code: SecureChatErrorCode, description: String) -> NSError {
        return NSError(domain: SecureChat.ErrorDomain, code: code.rawValue, userInfo: [NSLocalizedDescriptionKey: description])
    }
}

// MARK: Active session
extension SecureChat {
    public func activeSession(withParticipantWithCardId cardId: String) -> SecureSession? {
        Log.debug("SecureChat:\(self.preferences.identityCard.identifier). Searching for active session for: \(cardId)")
        
        guard case let sessionState?? = try? self.sessionHelper.getNewestSessionState(forRecipientCardId: cardId) else {
            return nil
        }
        
        guard !sessionState.isExpired(now: Date()) else {
            do {
                try self.removeSession(withParticipantWithCardId: cardId, sessionId: sessionState.sessionId)
            }
            catch {
                Log.error("SecureChat:\(self.preferences.identityCard.identifier). WARNING: Error occured while removing expired session in activeSession")
            }
            return nil
        }
        
        let secureSession = try? self.recoverSession(myIdentityCard: self.preferences.identityCard, sessionState: sessionState)
    
        return secureSession
    }
}

// MARK: Session initiation
extension SecureChat {
    private func startNewSession(withRecipientWithCard recipientCard: VSSCard, recipientCardsSet cardsSet: RecipientCardsSet, additionalData: Data?) throws -> SecureSession {
        Log.debug("SecureChat:\(self.preferences.identityCard.identifier). Starting new session with cards set with: \(recipientCard.identifier)")
        
        let identityCardId = recipientCard.identifier
        let identityPublicKeyData = recipientCard.publicKeyData
        let longTermPublicKeyData = cardsSet.longTermCard.publicKeyData
        let oneTimePublicKeyData = cardsSet.oneTimeCard?.publicKeyData
        
        let ephKeyPair = self.preferences.crypto.generateKeyPair()
        let ephPrivateKey = ephKeyPair.privateKey
        
        let validator = EphemeralCardValidator(crypto: self.preferences.crypto)

        do {
            try validator.addVerifier(withId: identityCardId, publicKeyData: identityPublicKeyData)
        }
        catch {
            throw SecureChat.makeError(withCode: .addingVerifier, description: "Error while adding verifier. Underlying error: \(error.localizedDescription)")
        }
        
        guard validator.validate(cardResponse: cardsSet.longTermCard.cardResponse) else {
            throw SecureChat.makeError(withCode: .longTermCardValidation, description: "Responder LongTerm card validation failed")
        }
        
        if let oneTimeCard = cardsSet.oneTimeCard {
            guard validator.validate(cardResponse: oneTimeCard.cardResponse) else {
                throw SecureChat.makeError(withCode: .oneTimeCardValidation, description: "Responder OneTime card validation failed.")
            }
        }
        
        let identityCardEntry = SecureSession.CardEntry(identifier: identityCardId, publicKeyData: identityPublicKeyData)
        let ltCardEntry = SecureSession.CardEntry(identifier: cardsSet.longTermCard.identifier, publicKeyData: longTermPublicKeyData)
        
        let otCardEntry: SecureSession.CardEntry?
        if let oneTimeCard = cardsSet.oneTimeCard, let oneTimePublicKeyData = oneTimePublicKeyData {
            otCardEntry = SecureSession.CardEntry(identifier: oneTimeCard.identifier, publicKeyData: oneTimePublicKeyData)
        }
        else {
            otCardEntry = nil
        }
        
        let date = Date()
        let secureSession = try self.sessionInitializer.initializeInitiatorSession(ephPrivateKey: ephPrivateKey, recipientIdCard: identityCardEntry, recipientLtCard: ltCardEntry, recipientOtCard: otCardEntry, additionalData: additionalData, creationDate: date, expirationDate: date.addingTimeInterval(self.preferences.sessionTtl))
     
        return secureSession
    }
    
    public func startNewSession(withRecipientWithCard recipientCard: VSSCard, additionalData: Data? = nil, completion: @escaping (SecureSession?, Error?)->()) {
        Log.debug("SecureChat:\(self.preferences.identityCard.identifier). Starting new session with: \(recipientCard.identifier)")
        
        // Check for existing session state
        let sessionState: SessionState?
        do {
            sessionState = try self.sessionHelper.getNewestSessionState(forRecipientCardId: recipientCard.identifier)
        }
        catch {
            completion(nil, SecureChat.makeError(withCode: .checkingForExistingSession, description: "Error checking for existing session. Underlying error: \(error.localizedDescription)"))
            return
        }
        
        // If we have existing session
        if let sessionState = sessionState {
            if !sessionState.isExpired(now: Date()) {
                Log.error("Found active session for \(recipientCard.identifier). Try to loadUpSession:, if that fails try to remove session.")
            }
            else {
                // If session is expired, just remove old session and create new one
                do {
                    try self.removeSession(withParticipantWithCardId: recipientCard.identifier, sessionId: sessionState.sessionId)
                }
                catch {
                    completion(nil, SecureChat.makeError(withCode: .removingExpiredSession, description: "Error removing expired session while creating new. Underlying error: \(error.localizedDescription)"))
                    return
                }
            }
        }
        
        // Get recipient's credentials
        self.client.getRecipientCardsSet(forCardsIds: [recipientCard.identifier]) { cardsSets, error in
            guard error == nil else {
                completion(nil, SecureChat.makeError(withCode: .obtainingRecipientCardsSet, description: "Error obtaining recipient cards set. Underlying error: \(error!.localizedDescription)"))
                return
            }
            
            guard let cardsSets = cardsSets, cardsSets.count > 0 else {
                completion(nil, SecureChat.makeError(withCode: .recipientSetEmpty, description: "Error obtaining recipient cards set. Empty set."))
                return
            }
            
            // FIXME: Multiple sessions?
            let cardsSet = cardsSets[0]
            
            do {
                let session = try self.startNewSession(withRecipientWithCard: recipientCard, recipientCardsSet: cardsSet, additionalData: additionalData)
                completion(session, nil)
                return
            }
            catch {
                completion(nil, error)
                return
            }
        }
    }
}
// MARK: Session responding
extension SecureChat {
    public func loadUpSession(withParticipantWithCard card: VSSCard, message: String, additionalData: Data? = nil) throws -> SecureSession {
        Log.debug("SecureChat:\(self.preferences.identityCard.identifier). Loading session with: \(card.identifier)")
        
        guard let messageData = message.data(using: .utf8) else {
            throw SecureChat.makeError(withCode: .invalidMessageString, description: "Invalid message string.")
        }
        
        if let initiationMessage = try? SecureSession.extractInitiationMessage(messageData) {
            // Add new one time card
            try? self.cardsHelper.addCards(forIdentityCard: self.preferences.identityCard, includeLtcCard: false, numberOfOtcCards: 1) { error in
                guard error == nil else {
                    Log.error("SecureChat:\(self.preferences.identityCard.identifier). WARNING: Error occured while adding new otc in loadUpSession")
                    return
                }
            }
            
            let cardEntry = SecureSession.CardEntry(identifier: card.identifier, publicKeyData: card.publicKeyData)
            
            let date = Date()
            let secureSession = try self.sessionInitializer.initializeResponderSession(initiatorCardEntry: cardEntry, initiationMessage: initiationMessage, additionalData: additionalData, creationDate: date, expirationDate: date.addingTimeInterval(self.preferences.sessionTtl))
            
            return secureSession
        }
        else if let message = try? SecureSession.extractMessage(messageData) {
            let sessionId = message.sessionId
            
            guard case let sessionState?? = try? self.sessionHelper.getSessionState(forRecipientCardId: card.identifier, sessionId: sessionId),
                sessionState.sessionId == sessionId else {
                throw SecureChat.makeError(withCode: .sessionNotFound, description: "Session not found.")
            }
            
            let session = try self.recoverSession(myIdentityCard: self.preferences.identityCard, sessionState: sessionState)
            
            return session
        }
        else {
            throw SecureChat.makeError(withCode: .unknownMessageStructure, description: "Unknown message structure.")
        }
    }
}

// MARK: Session recovering
extension SecureChat {
    fileprivate func recoverSession(myIdentityCard: VSSCard, sessionState: SessionState) throws -> SecureSession {
        Log.debug("SecureChat:\(self.preferences.identityCard.identifier). Recovering session: \(sessionState.sessionId.base64EncodedString())")
        
        let sessionKeys = try self.keyHelper.getSessionKeys(forSessionWithId: sessionState.sessionId)
        
        return try self.sessionInitializer.initializeSavedSession(sessionId: sessionState.sessionId, encryptionKey: sessionKeys.encryptionKey, decryptionKey: sessionKeys.decryptionKey, additionalData: sessionState.additionalData, expirationDate: sessionState.expirationDate)
    }
}

// MARK: Session removal
extension SecureChat {
    public func gentleReset() throws {
        Log.debug("SecureChat:\(self.preferences.identityCard.identifier). Gentle reset started")
        
        let sessionStates = try self.sessionHelper.getAllSessionsStates()
        
        for sessionState in sessionStates {
            try? self.removeSessions(withParticipantWithCardId: sessionState.key)
        }
    
        self.removeAllKeys()
    }
    
    private func removeAllKeys() {
        Log.debug("SecureChat:\(self.preferences.identityCard.identifier). Removing all keys.")
        
        self.keyHelper.gentleReset()
    }
    
    public func removeSessions(withParticipantWithCardId cardId: String) throws {
        Log.debug("SecureChat:\(self.preferences.identityCard.identifier). Removing sessions with: \(cardId)")
        
        let sessionStatesIds = try self.sessionHelper.getSessionStatesIds(forRecipientCardId: cardId)
        for sessionId in sessionStatesIds {
            var err: Error?
            do {
                try self.sessionHelper.removeSessionState(forCardId: cardId, sessionId: sessionId)
            }
            catch {
                err = error
            }
            
            try self.removeSessionKeys(forSessionId: sessionId)
            if let err = err {
                throw err
            }
        }
    }
    
    func removeSession(withParticipantWithCardId cardId: String, sessionId: Data) throws {
        Log.debug("SecureChat:\(self.preferences.identityCard.identifier). Removing session with: \(cardId), sessionId: \(sessionId.base64EncodedString())")
        
        try self.removeSessionKeys(forSessionId: sessionId)
        try self.sessionHelper.removeSessionState(forCardId: cardId, sessionId: sessionId)
    }
    
    private func removeSessionKeys(forUnknownSessionWithParticipantWithCardId cardId: String) throws {
        Log.debug("SecureChat:\(self.preferences.identityCard.identifier). Removing session keys for: \(cardId).")
        
        do {
            try self.keyHelper.removeOtPrivateKey(withName: cardId)
        }
        catch {
            throw SecureChat.makeError(withCode: .removingOtKey, description: "Error while removing ot key: \(error.localizedDescription)")
        }
    }
    
    private func removeSessionKeys(forSessionId sessionId: Data) throws {
        Log.debug("SecureChat:\(self.preferences.identityCard.identifier). Removing session keys for: \(sessionId.base64EncodedString()).")
        
        try self.keyHelper.removeSessionKeys(forSessionWithId: sessionId)
    }
}

// MARK: Keys rotation
extension SecureChat {
    // Workaround for Swift bug SR-2444
    public typealias CompletionHandler = (Error?) -> ()
    
    public func rotateKeys(desiredNumberOfCards: Int, completion: CompletionHandler? = nil) {
        self.rotator.rotateKeys(desiredNumberOfCards: desiredNumberOfCards, completion: completion)
    }
}
