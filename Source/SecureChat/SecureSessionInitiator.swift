//
//  SecureSessionInitiator.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCrypto
import VirgilSDK

class SecureSessionInitiator: SecureSessionBase {
    let myIdCard: VSSCard
    let ephPrivateKey: VSSPrivateKey
    let recipientIdCard: CardEntry
    let recipientLtCard: CardEntry
    let recipientOtCard: CardEntry?
    
    init(crypto: VSSCryptoProtocol, myPrivateKey: VSSPrivateKey, sessionHelper: SecureChatSessionHelper, keyHelper: SecureChatKeyHelper, additionalData: Data?, myIdCard: VSSCard, ephPrivateKey: VSSPrivateKey, recipientIdCard: CardEntry, recipientLtCard: CardEntry, recipientOtCard: CardEntry?, wasRecovered: Bool, creationDate: Date, expirationDate: Date) throws {
        self.myIdCard = myIdCard
        self.ephPrivateKey = ephPrivateKey
        self.recipientIdCard = recipientIdCard
        self.recipientLtCard = recipientLtCard
        self.recipientOtCard = recipientOtCard
        
        super.init(crypto: crypto, myPrivateKey: myPrivateKey, participantCardId: recipientIdCard.identifier, wasRecovered: wasRecovered, sessionHelper: sessionHelper, keyHelper: keyHelper, additionalData: additionalData, creationDate: creationDate, expirationDate: expirationDate)
        
        if self.wasRecovered {
            try self.initiateSession()
        }
    }
    
    override func saveSession(_ session: VSCPfsSession) throws {
        try super.saveSession(session)
        
        let sessionId = session.identifier
        let encryptionKey = session.encryptionSecretKey
        let decryptionKey = session.decryptionSecretKey
        let sessionKeys = SecureChatKeyHelper.SessionKeys(encryptionKey: encryptionKey, decryptionKey: decryptionKey)
        
        try self.keyHelper.saveSessionKeys(sessionKeys, forSessionWithId: sessionId)
        
        let sessionState = SessionState(creationDate: self.creationDate, expirationDate: self.expirationDate, sessionId: session.identifier, additionalData: session.additionalData)
        
        try self.sessionHelper.saveSessionState(sessionState, forRecipientCardId: self.participantCardId)
    }
}

// Encryption
extension SecureSessionInitiator {
    override func encrypt(_ message: String) throws -> String {
        let isFirstMessage: Bool
        if !self.isInitialized {
            isFirstMessage = true
            try self.initiateSession()
        }
        else {
            isFirstMessage = false
        }
        
        guard self.isInitialized else {
            throw SecureSession.makeError(withCode: .sessionStillNotInitializedWhileEncryptingInInitiatorSession, description: "Session is still not initialized while encrypting in initiator session.")
        }
        
        if isFirstMessage {
            guard let messageData = message.data(using: .utf8) else {
                throw SecureSession.makeError(withCode: .convertingInitiationMessageToDataWhileEncrypting, description: "Error converting initiation message to data while encrypting.")
            }
            
            guard let encryptedMessage = self.pfs.encryptData(messageData) else {
                throw SecureSession.makeError(withCode: .encryptingInitiationMessage, description: "Error while encrypting initiation message.")
            }

            let msg = Message(sessionId: encryptedMessage.sessionIdentifier, salt: encryptedMessage.salt, cipherText: encryptedMessage.cipherText)
            let ephPublicKey = self.crypto.extractPublicKey(from: self.ephPrivateKey)
            let ephPublicKeyData = self.crypto.export(ephPublicKey)
            let ephPublicKeySignature = try self.crypto.generateSignature(for: ephPublicKeyData, with: self.myPrivateKey)
            
            let initMsg = InitiationMessage(initiatorIcId: self.myIdCard.identifier, responderIcId: self.recipientIdCard.identifier, responderLtcId: self.recipientLtCard.identifier, responderOtcId: self.recipientOtCard?.identifier, ephPublicKey: ephPublicKeyData, ephPublicKeySignature: ephPublicKeySignature, salt: msg.salt, cipherText: msg.cipherText)
            
            let msgData = try JSONSerialization.data(withJSONObject: initMsg.serialize(), options: [])
            
            guard let msgStr = String(data: msgData, encoding: .utf8) else {
                throw SecureSession.makeError(withCode: .convertingEncryptedInitiationMessageToUtf8Data, description: "Error converting encrypted initiation message to data using utf8.")
            }
            
            return msgStr
        }
        else {
            return try super.encrypt(message)
        }
    }
    
    override func decrypt(_ encryptedMessage: String) throws -> String {
        guard self.isInitialized else {
            throw SecureSession.makeError(withCode: .sessionStillNotInitializedWhileDecryptingInInitiatorSession, description: "Session is still not initialized while decrypting in initiator session.")
        }
        
        guard let messageData = encryptedMessage.data(using: .utf8) else {
            throw SecureSession.makeError(withCode: .convertingEncryptedMessageToDataWhileDecryptingInInitiatorSession, description: "Error converting encrypted message to data while decrypting in initiator session.")
        }
        
        let message = try SecureSession.extractMessage(messageData)
        
        return try super.decrypt(encryptedMessage: message)
    }
}

// Session initialization
extension SecureSessionInitiator {
    fileprivate func initiateSession() throws {
        let privateKeyData = self.crypto.export(self.myPrivateKey, withPassword: nil)
        let ephPrivateKeyData = self.crypto.export(self.ephPrivateKey, withPassword: nil)
        guard let privateKey = VSCPfsPrivateKey(key: privateKeyData, password: nil),
            let ephPrivateKey = VSCPfsPrivateKey(key: ephPrivateKeyData, password: nil) else {
                throw SecureSession.makeError(withCode: .convertingInitiatorKeysDuringInitiatorInitialization, description: "Error while converting initiator crypto keys to pfs keys during initiator initialization.")
        }
        
        guard let initiatorPrivateInfo = VSCPfsInitiatorPrivateInfo(identityPrivateKey: privateKey, ephemeralPrivateKey: ephPrivateKey) else {
            throw SecureSession.makeError(withCode: .instantiationInitiatorPrivateInfo, description: "Error instantiating initiatorPrivateInfo.")
        }
        
        let responderPublicKeyData = self.recipientIdCard.publicKeyData
        let responderLongTermPublicKeyData = self.recipientLtCard.publicKeyData
        let responderOneTimePublicKeyData = self.recipientOtCard?.publicKeyData
        guard let responderPublicKey = VSCPfsPublicKey(key: responderPublicKeyData),
            let responderLongTermPublicKey = VSCPfsPublicKey(key: responderLongTermPublicKeyData) else {
                throw SecureSession.makeError(withCode: .convertingResponderKeysDuringInitiatorInitialization, description: "Error while converting responder crypto keys to pfs keys during initiator initialization.")
        }
        
        let responderOneTimePublicKey = responderOneTimePublicKeyData != nil ? VSCPfsPublicKey(key: responderOneTimePublicKeyData!) : nil
        
        guard let responderPublicInfo = VSCPfsResponderPublicInfo(identityPublicKey: responderPublicKey, longTermPublicKey: responderLongTermPublicKey, oneTime: responderOneTimePublicKey) else {
            throw SecureSession.makeError(withCode: .instantiationResponderPublicInfo, description: "Error instantiating responderPublicInfo.")
        }
        
        guard let session = self.pfs.startInitiatorSession(with: initiatorPrivateInfo, respondrerPublicInfo: responderPublicInfo, additionalData: self.additionalData) else {
            throw SecureSession.makeError(withCode: .initiatingInitiatorSession, description: "Error while initiating initiator session.")
        }
        
        if !self.wasRecovered {
            try self.saveSession(session)
        }
    }
}
