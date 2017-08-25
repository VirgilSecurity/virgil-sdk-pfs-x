//
//  SesssionManager.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/25/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

class SessionManager {
    fileprivate let identityCard: VSSCard
    fileprivate let crypto: VSSCryptoProtocol
    fileprivate let sessionTtl: TimeInterval
    fileprivate let keyHelper: SecureChatKeyHelper
    fileprivate let sessionHelper: SecureChatSessionHelper
    fileprivate let sessionInitializer: SessionInitializer
    
    init(identityCard: VSSCard, crypto: VSSCryptoProtocol, sessionTtl: TimeInterval, keyHelper: SecureChatKeyHelper, sessionHelper: SecureChatSessionHelper, sessionInitializer: SessionInitializer) {
        self.identityCard = identityCard
        self.crypto = crypto
        self.sessionTtl = sessionTtl
        self.keyHelper = keyHelper
        self.sessionHelper = sessionHelper
        self.sessionInitializer = sessionInitializer
    }
    
    func activeSession(withParticipantWithCardId cardId: String) -> SecureSession? {
        guard case let sessionState?? = try? self.sessionHelper.getNewestSessionState(forRecipientCardId: cardId) else {
            return nil
        }
        
        guard !sessionState.isExpired(now: Date()) else {
            do {
                try self.removeSession(withParticipantWithCardId: cardId, sessionId: sessionState.sessionId)
            }
            catch {
                Log.error("SessionManager: \(self.identityCard.identifier). WARNING: Error occured while removing expired session in activeSession")
            }
            return nil
        }
        
        let secureSession = try? self.recoverSession(myIdentityCard: self.identityCard, sessionState: sessionState)
        
        return secureSession
    }
}

extension SessionManager {
    func saveSession(_ session: SecureSession, creationDate: Date, participantCardId: String) throws {
        let sessionId = session.sessionId
        let encryptionKey = session.encryptionKey
        let decryptionKey = session.decryptionKey
        
        let sessionKeys = SecureChatKeyHelper.SessionKeys(encryptionKey: encryptionKey, decryptionKey: decryptionKey)
        
        try self.keyHelper.saveSessionKeys(sessionKeys, forSessionWithId: sessionId)
        
        let sessionState = SessionState(creationDate: creationDate, expirationDate: session.expirationDate, sessionId: session.sessionId, additionalData: session.additionalData)

        try self.sessionHelper.addSessionState(sessionState, forRecipientCardId: participantCardId)
    }
}

extension SessionManager {
    func checkExistingSessionOnStart(recipientCardId: String) throws  {
        let sessionState: SessionState?
        do {
            sessionState = try self.sessionHelper.getNewestSessionState(forRecipientCardId: recipientCardId)
        }
        catch {
            throw SecureChat.makeError(withCode: .checkingForExistingSession, description: "Error checking for existing session. Underlying error: \(error.localizedDescription)")
        }
        
        // If we have existing session
        if let sessionState = sessionState {
            if !sessionState.isExpired(now: Date()) {
                Log.error("Found active session for \(recipientCardId). Try to loadUpSession:, if that fails try to remove session.")
            }
            else {
                // If session is expired, just remove old session and create new one
                do {
                    try self.removeSession(withParticipantWithCardId: recipientCardId, sessionId: sessionState.sessionId)
                }
                catch {
                    throw SecureChat.makeError(withCode: .removingExpiredSession, description: "Error removing expired session while creating new. Underlying error: \(error.localizedDescription)")
                }
            }
        }
    }
}

extension SessionManager {
    func loadSession(recipientCardId: String, sessionId: Data) throws -> SecureSession {
        guard case let sessionState?? = try? self.sessionHelper.getSessionState(forRecipientCardId: recipientCardId, sessionId: sessionId),
            sessionState.sessionId == sessionId else {
                throw SecureChat.makeError(withCode: .sessionNotFound, description: "Session not found.")
        }
        
        let session = try self.recoverSession(myIdentityCard: self.identityCard, sessionState: sessionState)
        
        return session
    }
}

extension SessionManager {
    func initializeResponderSession(initiatorCardEntry: CardEntry, initiationMessage: InitiationMessage, additionalData: Data?) throws -> SecureSession {
        let creationDate = Date()
        let expirationDate = creationDate.addingTimeInterval(self.sessionTtl)
        
        let secureSession = try self.sessionInitializer.initializeResponderSession(initiatorCardEntry: initiatorCardEntry, initiationMessage: initiationMessage, additionalData: additionalData, expirationDate: expirationDate)
        
        try self.saveSession(secureSession, creationDate: creationDate, participantCardId: initiatorCardEntry.identifier)
        
        return secureSession
    }
    
    func initializeInitiatorSession(withRecipientWithCard recipientCard: VSSCard, recipientCardsSet cardsSet: RecipientCardsSet, additionalData: Data?) throws -> SecureSession {
        
        if cardsSet.oneTimeCard == nil {
            Log.error("WARNING: Creating weak session with \(recipientCard.identifier).")
        }
        
        let identityCardId = recipientCard.identifier
        let identityPublicKeyData = recipientCard.publicKeyData
        let longTermPublicKeyData = cardsSet.longTermCard.publicKeyData
        let oneTimePublicKeyData = cardsSet.oneTimeCard?.publicKeyData
        
        let ephKeyPair = self.crypto.generateKeyPair()
        let ephPrivateKey = ephKeyPair.privateKey
        
        let validator = EphemeralCardValidator(crypto: self.crypto)
        
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
        
        let identityCardEntry = CardEntry(identifier: identityCardId, publicKeyData: identityPublicKeyData)
        let ltCardEntry = CardEntry(identifier: cardsSet.longTermCard.identifier, publicKeyData: longTermPublicKeyData)
        
        let otCardEntry: CardEntry?
        if let oneTimeCard = cardsSet.oneTimeCard, let oneTimePublicKeyData = oneTimePublicKeyData {
            otCardEntry = CardEntry(identifier: oneTimeCard.identifier, publicKeyData: oneTimePublicKeyData)
        }
        else {
            otCardEntry = nil
        }
        
        let creationDate = Date()
        let expirationDate = creationDate.addingTimeInterval(self.sessionTtl)
        
        let secureSession = try self.sessionInitializer.initializeInitiatorSession(ephPrivateKey: ephPrivateKey, recipientIdCard: identityCardEntry, recipientLtCard: ltCardEntry, recipientOtCard: otCardEntry, additionalData: additionalData, expirationDate: expirationDate)
        
        try self.saveSession(secureSession, creationDate: creationDate, participantCardId: recipientCard.identifier)
        
        return secureSession
    }
}

// MARK: Session recovering
extension SessionManager {
    fileprivate func recoverSession(myIdentityCard: VSSCard, sessionState: SessionState) throws -> SecureSession {
        Log.debug("SessionManager: \(self.identityCard.identifier). Recovering session: \(sessionState.sessionId.base64EncodedString())")
        
        let sessionKeys = try self.keyHelper.getSessionKeys(forSessionWithId: sessionState.sessionId)
        
        return try self.sessionInitializer.initializeSavedSession(sessionId: sessionState.sessionId, encryptionKey: sessionKeys.encryptionKey, decryptionKey: sessionKeys.decryptionKey, additionalData: sessionState.additionalData, expirationDate: sessionState.expirationDate)
    }
}

// MARK: Session removal
extension SessionManager {
    func gentleReset() throws {
        Log.debug("SessionManager: \(self.identityCard.identifier). Gentle reset started")
        
        let sessionStates = try self.sessionHelper.getAllSessionsStates()
        
        for sessionState in sessionStates {
            try? self.removeSessions(withParticipantWithCardId: sessionState.key)
        }
        
        self.removeAllKeys()
    }
    
    private func removeAllKeys() {
        Log.debug("SessionManager: \(self.identityCard.identifier). Removing all keys.")
        
        self.keyHelper.gentleReset()
    }
    
    func removeSessions(withParticipantWithCardId cardId: String) throws {
        Log.debug("SessionManager: \(self.identityCard.identifier). Removing sessions with: \(cardId)")
        
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
        Log.debug("SessionManager: \(self.identityCard.identifier). Removing session with: \(cardId), sessionId: \(sessionId.base64EncodedString())")
        
        try self.removeSessionKeys(forSessionId: sessionId)
        try self.sessionHelper.removeSessionState(forCardId: cardId, sessionId: sessionId)
    }
    
    private func removeSessionKeys(forUnknownSessionWithParticipantWithCardId cardId: String) throws {
        Log.debug("SessionManager: \(self.identityCard.identifier). Removing session keys for: \(cardId).")
        
        do {
            try self.keyHelper.removeOtPrivateKey(withName: cardId)
        }
        catch {
            throw SecureChat.makeError(withCode: .removingOtKey, description: "Error while removing ot key: \(error.localizedDescription)")
        }
    }
    
    private func removeSessionKeys(forSessionId sessionId: Data) throws {
        Log.debug("SessionManager: \(self.identityCard.identifier). Removing session keys for: \(sessionId.base64EncodedString()).")
        
        try self.keyHelper.removeSessionKeys(forSessionWithId: sessionId)
    }
}
