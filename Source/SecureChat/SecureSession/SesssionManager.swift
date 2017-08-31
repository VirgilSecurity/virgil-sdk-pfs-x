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
    fileprivate let identityPrivateKey: VSSPrivateKey
    fileprivate let crypto: VSSCryptoProtocol
    fileprivate let sessionTtl: TimeInterval
    fileprivate let keyStorageManager: KeyStorageManager
    fileprivate let sessionStorageManager: SessionStorageManager
    fileprivate let sessionInitializer: SessionInitializer
    
    init(identityCard: VSSCard, identityPrivateKey: VSSPrivateKey, crypto: VSSCryptoProtocol, sessionTtl: TimeInterval, keyStorageManager: KeyStorageManager, sessionStorageManager: SessionStorageManager, sessionInitializer: SessionInitializer) {
        self.identityCard = identityCard
        self.identityPrivateKey = identityPrivateKey
        self.crypto = crypto
        self.sessionTtl = sessionTtl
        self.keyStorageManager = keyStorageManager
        self.sessionStorageManager = sessionStorageManager
        self.sessionInitializer = sessionInitializer
    }
    
    func activeSession(withParticipantWithCardId cardId: String) -> SecureSession? {
        guard case let sessionState?? = try? self.sessionStorageManager.getNewestSessionState(forRecipientCardId: cardId),
            !sessionState.isExpired() else {
                return nil
        }
        
        let secureSession = try? self.recoverSession(myIdentityCard: self.identityCard, sessionState: sessionState)
        
        return secureSession
    }
}

extension SessionManager {
    func saveSession(_ session: SecureSession, creationDate: Date, participantCardId: String) throws {
        let sessionId = session.identifier
        let encryptionKey = session.encryptionKey
        let decryptionKey = session.decryptionKey
        
        let sessionKeys = KeyStorageManager.SessionKeys(encryptionKey: encryptionKey, decryptionKey: decryptionKey)
        
        try self.keyStorageManager.saveSessionKeys(sessionKeys, forSessionWithId: sessionId)
        
        let sessionState = SessionState(creationDate: creationDate, expirationDate: session.expirationDate, sessionId: session.identifier, additionalData: session.additionalData)

        try self.sessionStorageManager.addSessionState(sessionState, forRecipientCardId: participantCardId)
    }
}

extension SessionManager {
    func checkExistingSessionOnStart(recipientCardId: String) throws  {
        let sessionState: SessionState?
        do {
            sessionState = try self.sessionStorageManager.getNewestSessionState(forRecipientCardId: recipientCardId)
        }
        catch {
            throw SecureChat.makeError(withCode: .checkingForExistingSession, description: "Error checking for existing session. Underlying error: \(error.localizedDescription)")
        }
        
        if let sessionState = sessionState, !sessionState.isExpired() {
            Log.error("Found active session for \(recipientCardId). Try to loadUpSession:, if that fails try to remove session.")
        }
    }
}

extension SessionManager {
    func loadSession(recipientCardId: String, sessionId: Data) throws -> SecureSession {
        guard case let sessionState?? = try? self.sessionStorageManager.getSessionState(forRecipientCardId: recipientCardId, sessionId: sessionId),
            sessionState.sessionId == sessionId else {
                throw SecureChat.makeError(withCode: .sessionNotFound, description: "Session not found.")
        }
        
        let session = try self.recoverSession(myIdentityCard: self.identityCard, sessionState: sessionState)
        
        return session
    }
}

extension SessionManager {
    func initializeResponderSession(initiatorCardEntry: CardEntry, initiationMessage: InitiationMessage, additionalData: Data?) throws -> SecureSession {
        guard let initiatorPublicKey = self.crypto.importPublicKey(from: initiatorCardEntry.publicKeyData) else {
            throw SecureSession.makeError(withCode: .importingInitiatorPublicKeyFromIdentityCard, description: "Error importing initiator public key from identity card.")
        }
        
        do {
            try self.crypto.verify(initiationMessage.ephPublicKey, withSignature: initiationMessage.ephPublicKeySignature, using: initiatorPublicKey)
        }
        catch {
            throw SecureSession.makeError(withCode: .validatingInitiatorSignature, description: "Error validating initiator signature.")
        }
        
        guard initiationMessage.initiatorIcId == initiatorCardEntry.identifier else {
            throw SecureSession.makeError(withCode: .initiatorIdentityCardIdDoesntMatch, description: "Initiator identity card id for this session and InitiationMessage doesn't match.")
        }
        
        let ltPrivateKey = try self.keyStorageManager.getLtPrivateKey(withName: initiationMessage.responderLtcId)
        
        let otPrivateKey: VSSPrivateKey?
        if let recponderOtcId = initiationMessage.responderOtcId {
            otPrivateKey = try self.keyStorageManager.getOtPrivateKey(withName: recponderOtcId)
            try self.keyStorageManager.removeOtPrivateKey(withName: recponderOtcId)
        }
        else {
            otPrivateKey = nil
        }
        
        let creationDate = Date()
        let expirationDate = creationDate.addingTimeInterval(self.sessionTtl)
        
        let secureSession = try self.sessionInitializer.initializeResponderSession(initiatorCardEntry: initiatorCardEntry, privateKey: self.identityPrivateKey, ltPrivateKey: ltPrivateKey, otPrivateKey: otPrivateKey, ephPublicKey: initiationMessage.ephPublicKey, additionalData: additionalData, expirationDate: expirationDate)
        
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
        
        let sessionKeys = try self.keyStorageManager.getSessionKeys(forSessionWithId: sessionState.sessionId)
        
        return try self.sessionInitializer.initializeSavedSession(sessionId: sessionState.sessionId, encryptionKey: sessionKeys.encryptionKey, decryptionKey: sessionKeys.decryptionKey, additionalData: sessionState.additionalData, expirationDate: sessionState.expirationDate)
    }
}

// MARK: Session removal
extension SessionManager {
    func gentleReset() throws {
        Log.debug("SessionManager: \(self.identityCard.identifier). Gentle reset started")
        
        let sessionStates = try self.sessionStorageManager.getAllSessionsStates()
        
        for sessionState in sessionStates {
            try? self.removeSessions(withParticipantWithCardId: sessionState.0)
        }
        
        self.removeAllKeys()
    }
    
    private func removeAllKeys() {
        Log.debug("SessionManager: \(self.identityCard.identifier). Removing all keys.")
        
        self.keyStorageManager.gentleReset()
    }
    
    func removeSessions(withParticipantWithCardId cardId: String) throws {
        Log.debug("SessionManager: \(self.identityCard.identifier). Removing sessions with: \(cardId)")
        
        let sessionStatesIds = try self.sessionStorageManager.getSessionStatesIds(forRecipientCardId: cardId)
        for sessionId in sessionStatesIds {
            var err: Error?
            do {
                try self.sessionStorageManager.removeSessionState(forCardId: cardId, sessionId: sessionId)
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
        try self.sessionStorageManager.removeSessionState(forCardId: cardId, sessionId: sessionId)
    }
    
    private func removeSessionKeys(forUnknownSessionWithParticipantWithCardId cardId: String) throws {
        Log.debug("SessionManager: \(self.identityCard.identifier). Removing session keys for: \(cardId).")
        
        do {
            try self.keyStorageManager.removeOtPrivateKey(withName: cardId)
        }
        catch {
            throw SecureChat.makeError(withCode: .removingOtKey, description: "Error while removing ot key: \(error.localizedDescription)")
        }
    }
    
    private func removeSessionKeys(forSessionId sessionId: Data) throws {
        Log.debug("SessionManager: \(self.identityCard.identifier). Removing session keys for: \(sessionId.base64EncodedString()).")
        
        try self.keyStorageManager.removeSessionKeys(forSessionWithId: sessionId)
    }
}
