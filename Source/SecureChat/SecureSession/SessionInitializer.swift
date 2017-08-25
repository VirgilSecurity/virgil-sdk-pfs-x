//
//  SessionInitializer.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/25/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCrypto
import VirgilSDK

class SessionInitializer {
    private let crypto: VSSCryptoProtocol
    private let identityPrivateKey: VSSPrivateKey
    private let identityCard: VSSCard
    private let sessionHelper: SecureChatSessionHelper
    private let keyHelper: SecureChatKeyHelper
    
    init(crypto: VSSCryptoProtocol, identityPrivateKey: VSSPrivateKey, identityCard: VSSCard, sessionHelper: SecureChatSessionHelper, keyHelper: SecureChatKeyHelper) {
        self.crypto = crypto
        self.identityPrivateKey = identityPrivateKey
        self.identityCard = identityCard
        self.sessionHelper = sessionHelper
        self.keyHelper = keyHelper
    }
    
    func initializeInitiatorSession(ephPrivateKey: VSSPrivateKey, recipientIdCard: SecureSession.CardEntry, recipientLtCard: SecureSession.CardEntry, recipientOtCard: SecureSession.CardEntry?, additionalData: Data?, creationDate: Date, expirationDate: Date) throws -> SecureSession {
        let privateKeyData = self.crypto.export(self.identityPrivateKey, withPassword: nil)
        let ephPrivateKeyData = self.crypto.export(ephPrivateKey, withPassword: nil)
        guard let pfsPrivateKey = VSCPfsPrivateKey(key: privateKeyData, password: nil),
            let pfsEphPrivateKey = VSCPfsPrivateKey(key: ephPrivateKeyData, password: nil) else {
                throw SecureSession.makeError(withCode: .convertingInitiatorKeysDuringInitiatorInitialization, description: "Error while converting initiator crypto keys to pfs keys during initiator initialization.")
        }
        
        guard let initiatorPrivateInfo = VSCPfsInitiatorPrivateInfo(identityPrivateKey: pfsPrivateKey, ephemeralPrivateKey: pfsEphPrivateKey) else {
            throw SecureSession.makeError(withCode: .instantiationInitiatorPrivateInfo, description: "Error instantiating initiatorPrivateInfo.")
        }
        
        let responderPublicKeyData = recipientIdCard.publicKeyData
        let responderLongTermPublicKeyData = recipientLtCard.publicKeyData
        let responderOneTimePublicKeyData = recipientOtCard?.publicKeyData
        guard let pfsResponderPublicKey = VSCPfsPublicKey(key: responderPublicKeyData),
            let pfsResponderLongTermPublicKey = VSCPfsPublicKey(key: responderLongTermPublicKeyData) else {
                throw SecureSession.makeError(withCode: .convertingResponderKeysDuringInitiatorInitialization, description: "Error while converting responder crypto keys to pfs keys during initiator initialization.")
        }
        
        let pfsResponderOneTimePublicKey = responderOneTimePublicKeyData != nil ? VSCPfsPublicKey(key: responderOneTimePublicKeyData!) : nil
        
        guard let responderPublicInfo = VSCPfsResponderPublicInfo(identityPublicKey: pfsResponderPublicKey, longTermPublicKey: pfsResponderLongTermPublicKey, oneTime: pfsResponderOneTimePublicKey) else {
            throw SecureSession.makeError(withCode: .instantiationResponderPublicInfo, description: "Error instantiating responderPublicInfo.")
        }
        
        let pfs = VSCPfs()
        guard let session = pfs.startInitiatorSession(with: initiatorPrivateInfo, respondrerPublicInfo: responderPublicInfo, additionalData: additionalData) else {
            throw SecureSession.makeError(withCode: .initiatingInitiatorSession, description: "Error while initiating initiator session.")
        }
        
        let ephPublicKey = self.crypto.extractPublicKey(from: ephPrivateKey)
        let ephPublicKeyData = self.crypto.export(ephPublicKey)
        let ephPublicKeySignature = try self.crypto.generateSignature(for: ephPublicKeyData, with: self.identityPrivateKey)
        
        let firstMessageGenerator: (SecureSession, String) throws -> String = { secureSession, message in
            let firstMessage = try secureSession.encryptInitiationMessage(message, ephPublicKeyData: ephPublicKeyData, ephPublicKeySignature: ephPublicKeySignature, initiatorIcId: self.identityCard.identifier, responderIcId: recipientIdCard.identifier, responderLtcId: recipientLtCard.identifier, responderOtcId: recipientOtCard?.identifier)
            
            return firstMessage
        }
        
        let secureSession = SecureSession(pfsSession: session, expirationDate: expirationDate, firstMsgGenerator: firstMessageGenerator)
        
        try self.saveSession(session, participantCardId: recipientIdCard.identifier, creationDate: creationDate, expirationDate: expirationDate)
        
        return secureSession
    }
    
    func initializeResponderSession(initiatorCardEntry: SecureSession.CardEntry, initiationMessage: InitiationMessage, additionalData: Data?, creationDate: Date, expirationDate: Date) throws -> SecureSession {
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

        let privateKeyData = self.crypto.export(self.identityPrivateKey, withPassword: nil)

        let myLtPrivateKey = try self.keyHelper.getLtPrivateKey(withName: initiationMessage.responderLtcId)
        
        let myOtPrivateKey: VSSPrivateKey?
        if let recponderOtcId = initiationMessage.responderOtcId {
            myOtPrivateKey = try self.keyHelper.getOtPrivateKey(name: recponderOtcId)
        }
        else {
            myOtPrivateKey = nil
        }

        let ltPrivateKeyData = self.crypto.export(myLtPrivateKey, withPassword: nil)
        let otPrivateKeyData = myOtPrivateKey != nil ? self.crypto.export(myOtPrivateKey!, withPassword: nil) : nil
        guard let privateKey = VSCPfsPrivateKey(key: privateKeyData, password: nil),
            let ltPrivateKey = VSCPfsPrivateKey(key: ltPrivateKeyData, password: nil) else {
                throw SecureSession.makeError(withCode: .convertingResponderKeysDuringResponderInitialization, description: "Error while converting responder crypto keys to pfs keys during responder initialization.")
        }

        let otPrivateKey = otPrivateKeyData != nil ? VSCPfsPrivateKey(key: otPrivateKeyData!, password: nil) : nil

        guard let responderPrivateInfo = VSCPfsResponderPrivateInfo(identityPrivateKey: privateKey, longTermPrivateKey: ltPrivateKey, oneTime: otPrivateKey) else {
            throw SecureSession.makeError(withCode: .instantiationResponderPrivateInfo, description: "Error instantiating responderPrivateInfo.")
        }

        guard let initiatorEphPublicKey = VSCPfsPublicKey(key: initiationMessage.ephPublicKey),
            let initiatorIdPublicKey = VSCPfsPublicKey(key: initiatorCardEntry.publicKeyData) else {
                throw SecureSession.makeError(withCode: .convertingInitiatorKeysDuringResponderInitialization, description: "Error while converting initiator crypto keys to pfs keys during responder initialization.")
        }

        guard let initiatorPublicInfo = VSCPfsInitiatorPublicInfo(identityPublicKey: initiatorIdPublicKey, ephemeralPublicKey: initiatorEphPublicKey) else {
            throw SecureSession.makeError(withCode: .instantiatingInitiatorPublicInfo, description: "Error instantiating initiatorPublicInfo.")
        }

        let pfs = VSCPfs()
        guard let session = pfs.startResponderSession(with: responderPrivateInfo, initiatorPublicInfo: initiatorPublicInfo, additionalData: additionalData) else {
            throw SecureSession.makeError(withCode: .initiatingResponderSession, description: "Error while initiating responder session.")
        }
        
        try self.saveSession(session, participantCardId: initiatorCardEntry.identifier, creationDate: creationDate, expirationDate: expirationDate)
        
        return SecureSession(pfsSession: session, expirationDate: expirationDate, firstMsgGenerator: nil)
    }
    
    // FIXME: Move this somewhere
    func saveSession(_ session: VSCPfsSession, participantCardId: String, creationDate: Date, expirationDate: Date) throws {
        let sessionId = session.identifier
        let encryptionKey = session.encryptionSecretKey
        let decryptionKey = session.decryptionSecretKey
        let sessionKeys = SecureChatKeyHelper.SessionKeys(encryptionKey: encryptionKey, decryptionKey: decryptionKey)

        try self.keyHelper.saveSessionKeys(sessionKeys, forSessionWithId: sessionId)

        let sessionState = SessionState(creationDate: creationDate, expirationDate: expirationDate, sessionId: session.identifier, additionalData: session.additionalData)

        try self.sessionHelper.addSessionState(sessionState, forRecipientCardId: participantCardId)
    }
    
    func initializeSavedSession(sessionId: Data, encryptionKey: Data, decryptionKey: Data, additionalData: Data, expirationDate: Date) throws -> SecureSession {
        guard let session = VSCPfsSession(identifier: sessionId, encryptionSecretKey: encryptionKey, decryptionSecretKey: decryptionKey, additionalData: additionalData) else {
            throw SecureSession.makeError(withCode: .recoveringInitiatedSession, description: "Error creating session using symmetric keys.")
        }
        
        return SecureSession(pfsSession: session, expirationDate: expirationDate, firstMsgGenerator: nil)
    }
}
