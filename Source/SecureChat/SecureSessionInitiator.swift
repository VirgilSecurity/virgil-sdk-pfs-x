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

class SecureSessionInitiator: SecureSession {
    let myIdCard: VSSCard
    let ephPrivateKey: VSSPrivateKey
    let ephPrivateKeyName: String
    let recipientIdCard: CardEntry
    let recipientLtCard: CardEntry
    let recipientOtCard: CardEntry?
    
    init(crypto: VSSCryptoProtocol, myPrivateKey: VSSPrivateKey, sessionHelper: SecureChatSessionHelper, additionalData: Data?, myIdCard: VSSCard, ephPrivateKey: VSSPrivateKey, ephPrivateKeyName: String, recipientIdCard: CardEntry, recipientLtCard: CardEntry, recipientOtCard: CardEntry?, wasRecovered: Bool, creationDate: Date, expirationDate: Date) throws {
        self.myIdCard = myIdCard
        self.ephPrivateKey = ephPrivateKey
        self.ephPrivateKeyName = ephPrivateKeyName
        self.recipientIdCard = recipientIdCard
        self.recipientLtCard = recipientLtCard
        self.recipientOtCard = recipientOtCard
        
        super.init(crypto: crypto, myPrivateKey: myPrivateKey, wasRecovered: wasRecovered, sessionHelper: sessionHelper, additionalData: additionalData, creationDate: creationDate, expirationDate: expirationDate)
        
        if self.wasRecovered {
            try self.initiateSession()
        }
    }
}

// Encryption
extension SecureSessionInitiator {
    override func encrypt(_ message: String) throws -> String {
        let isFirstMessage: Bool
        if !self.isSessionInitialized {
            isFirstMessage = true
            try self.initiateSession()
        }
        else {
            isFirstMessage = false
        }
        
        guard self.isSessionInitialized else {
            throw NSError(domain: SecureSession.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Session is still not initialized."])
        }
        
        if isFirstMessage {
            guard let messageData = message.data(using: .utf8) else {
                throw NSError(domain: SecureSession.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error converting message to data."])
            }
            
            guard let encryptedMessage = self.pfs.encryptData(messageData) else {
                throw NSError(domain: SecureSession.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while encrypting message."])
            }

            let msg = Message(sessionId: encryptedMessage.sessionIdentifier, salt: encryptedMessage.salt, cipherText: encryptedMessage.cipherText)
            let ephPublicKey = self.crypto.extractPublicKey(from: self.ephPrivateKey)
            let ephPublicKeyData = self.crypto.export(ephPublicKey)
            let ephPublicKeySignature = try self.crypto.generateSignature(for: ephPublicKeyData, with: self.myPrivateKey)
            
            let initMsg = InitiationMessage(initiatorIcId: self.myIdCard.identifier, responderIcId: self.recipientIdCard.identifier, responderLtcId: self.recipientLtCard.identifier, responderOtcId: self.recipientOtCard?.identifier, ephPublicKey: ephPublicKeyData, ephPublicKeySignature: ephPublicKeySignature, salt: msg.salt, cipherText: msg.cipherText)
            
            let msgData = try JSONSerialization.data(withJSONObject: initMsg.serialize(), options: [])
            
            guard let msgStr = String(data: msgData, encoding: .utf8) else {
                throw NSError(domain: SecureSession.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error converting message to data using utf8."])
            }
            
            return msgStr
        }
        else {
            return try super.encrypt(message)
        }
    }
    
    override func decrypt(_ encryptedMessage: String) throws -> String {
        guard self.isSessionInitialized else {
            throw NSError(domain: SecureSession.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Session is still not initialized."])
        }
        
        guard let messageData = encryptedMessage.data(using: .utf8) else {
            throw NSError(domain: SecureSession.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error converting encrypted message while decrypting."])
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
                throw NSError(domain: SecureSession.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while convering crypto keys to pfs keys."])
        }
        
        guard let initiatorPrivateInfo = VSCPfsInitiatorPrivateInfo(identityPrivateKey: privateKey, ephemeralPrivateKey: ephPrivateKey) else {
            throw NSError(domain: SecureSession.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error instantiating initiatorPrivateInfo."])
        }
        
        let responderPublicKeyData = self.recipientIdCard.publicKeyData
        let responderLongTermPublicKeyData = self.recipientLtCard.publicKeyData
        let responderOneTimePublicKeyData = self.recipientOtCard?.publicKeyData
        guard let responderPublicKey = VSCPfsPublicKey(key: responderPublicKeyData),
            let responderLongTermPublicKey = VSCPfsPublicKey(key: responderLongTermPublicKeyData) else {
                throw NSError(domain: SecureSession.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while convering crypto keys to pfs keys."])
        }
        
        let responderOneTimePublicKey = responderOneTimePublicKeyData != nil ? VSCPfsPublicKey(key: responderOneTimePublicKeyData!) : nil
        
        guard let responderPublicInfo = VSCPfsResponderPublicInfo(identityPublicKey: responderPublicKey, longTermPublicKey: responderLongTermPublicKey, oneTime: responderOneTimePublicKey) else {
            throw NSError(domain: SecureSession.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error instantiating responderPublicInfo."])
        }
        
        guard let session = self.pfs.startInitiatorSession(with: initiatorPrivateInfo, respondrerPublicInfo: responderPublicInfo, additionalData: self.additionalData) else {
            throw NSError(domain: SecureSession.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while initiating initiator session."])
        }
        
        if !self.wasRecovered {
            let sessionId = session.identifier
            let sessionState = InitiatorSessionState(creationDate: self.creationDate, expirationDate: self.expirationDate, sessionId: sessionId, additionalData: self.additionalData, ephKeyName: self.ephPrivateKeyName, recipientCardId: self.recipientIdCard.identifier, recipientPublicKey: self.recipientIdCard.publicKeyData, recipientLongTermCardId: self.recipientLtCard.identifier, recipientLongTermPublicKey: self.recipientLtCard.publicKeyData, recipientOneTimeCardId: self.recipientOtCard?.identifier, recipientOneTimePublicKey: self.recipientOtCard?.publicKeyData)
            
            try self.sessionHelper.saveSessionState(sessionState, forRecipientCardId: self.recipientIdCard.identifier)
        }
    }
}
