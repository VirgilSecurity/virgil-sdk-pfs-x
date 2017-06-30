//
//  SecureTalkInitiator.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCrypto
import VirgilSDK

class SecureTalkInitiator: SecureTalk {
    let myIdCard: VSSCard
    let ephPrivateKey: VSSPrivateKey
    let ephPrivateKeyName: String
    let recipientIdCard: CardEntry
    let recipientLtCard: CardEntry
    let recipientOtCard: CardEntry
    
    init(crypto: VSSCryptoProtocol, myPrivateKey: VSSPrivateKey, sessionHelper: SecureChatSessionHelper, additionalData: Data?, myIdCard: VSSCard, ephPrivateKey: VSSPrivateKey, ephPrivateKeyName: String, recipientIdCard: CardEntry, recipientLtCard: CardEntry, recipientOtCard: CardEntry, wasRecovered: Bool, ttl: TimeInterval) throws {
        self.myIdCard = myIdCard
        self.ephPrivateKey = ephPrivateKey
        self.ephPrivateKeyName = ephPrivateKeyName
        self.recipientIdCard = recipientIdCard
        self.recipientLtCard = recipientLtCard
        self.recipientOtCard = recipientOtCard
        
        super.init(crypto: crypto, myPrivateKey: myPrivateKey, wasRecovered: wasRecovered, sessionHelper: sessionHelper, additionalData: additionalData, ttl: ttl)
        
        if self.wasRecovered {
            try self.initiateSession()
        }
    }
}

// Encryption
extension SecureTalkInitiator {
    override func encrypt(_ message: String) throws -> Data {
        let isFirstMessage: Bool
        if !self.isSessionInitialized {
            isFirstMessage = true
            try self.initiateSession()
        }
        else {
            isFirstMessage = false
        }
        
        guard self.isSessionInitialized else {
            throw NSError(domain: SecureTalk.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Session is still not initialized."])
        }
        
        if isFirstMessage {
            guard let messageData = message.data(using: .utf8) else {
                throw NSError(domain: SecureTalk.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error converting message to data."])
            }
            
            guard let encryptedMessage = self.pfs.encryptData(messageData) else {
                throw NSError(domain: SecureTalk.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while encrypting message."])
            }
            // FIXME: Add support for weak sessions
            let msg = Message(sessionId: encryptedMessage.sessionIdentifier, salt: encryptedMessage.salt, cipherText: encryptedMessage.cipherText)
            let weakSessionData = WeakSessionData(salt: msg.salt, cipherText: msg.cipherText)
            let strongSessionData = StrongSessionData(receiverOtcId: self.recipientOtCard.identifier, salt: msg.salt, cipherText: msg.cipherText)
            let ephPublicKey = self.crypto.extractPublicKey(from: self.ephPrivateKey)
            let ephPublicKeyData = self.crypto.export(ephPublicKey)
            let ephPublicKeySignature = try self.crypto.generateSignature(for: ephPublicKeyData, with: self.myPrivateKey)
            
            let initMsg = InitiationMessage(initiatorIcId: self.myIdCard.identifier, receiverIcId: self.recipientIdCard.identifier, receiverLtcId: self.recipientLtCard.identifier, ephPublicKey: ephPublicKeyData, ephPublicKeySignature: ephPublicKeySignature, weakSessionData: weakSessionData, strongSessionData: strongSessionData)
            
            let msgData = try JSONSerialization.data(withJSONObject: initMsg.serialize(), options: [])
            return msgData
        }
        else {
            // FIXME: Add support for weak sessions
            
            return try super.encrypt(message)
        }
    }
    
    override func decrypt(_ encryptedMessage: Data) throws -> String {
        guard self.isSessionInitialized else {
            throw NSError(domain: SecureTalk.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Session is still not initialized."])
        }
        
        return try super.decrypt(encryptedMessage)
    }
}

// Session initialization
extension SecureTalkInitiator {
    fileprivate func initiateSession() throws {
        let privateKeyData = self.crypto.export(self.myPrivateKey, withPassword: nil)
        let ephPrivateKeyData = self.crypto.export(self.ephPrivateKey, withPassword: nil)
        guard let privateKey = VSCPfsPrivateKey(key: privateKeyData, password: nil),
            let ephPrivateKey = VSCPfsPrivateKey(key: ephPrivateKeyData, password: nil) else {
                throw NSError(domain: SecureTalk.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while convering crypto keys to pfs keys."])
        }
        
        guard let initiatorPrivateInfo = VSCPfsInitiatorPrivateInfo(identityPrivateKey: privateKey, ephemeralPrivateKey: ephPrivateKey) else {
            throw NSError(domain: SecureTalk.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error instantiating initiatorPrivateInfo."])
        }
        
        let responderPublicKeyData = self.recipientIdCard.publicKeyData
        let responderLongTermPublicKeyData = self.recipientLtCard.publicKeyData
        let responderOneTimePublicKeyData = self.recipientOtCard.publicKeyData
        guard let responderPublicKey = VSCPfsPublicKey(key: responderPublicKeyData),
            let responderLongTermPublicKey = VSCPfsPublicKey(key: responderLongTermPublicKeyData),
            let responderOneTimePublicKey = VSCPfsPublicKey(key: responderOneTimePublicKeyData) else {
                throw NSError(domain: SecureTalk.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while convering crypto keys to pfs keys."])
        }
        
        guard let responderPublicInfo = VSCPfsResponderPublicInfo(identityPublicKey: responderPublicKey, longTermPublicKey: responderLongTermPublicKey, oneTime: responderOneTimePublicKey) else {
            throw NSError(domain: SecureTalk.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error instantiating responderPublicInfo."])
        }
        
        guard let session = self.pfs.startInitiatorSession(with: initiatorPrivateInfo, respondrerPublicInfo: responderPublicInfo, additionalData: self.additionalData) else {
            throw NSError(domain: SecureTalk.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while initiating initiator session."])
        }
        
        if !self.wasRecovered {
            let date = Date()
            let expirationDate = date.addingTimeInterval(self.ttl)
            let sessionId = session.identifier
            
            // FIXME: Optional one time key?
            let sessionState = InitiatorSessionState(creationDate: date, expirationDate: expirationDate, sessionId: sessionId, additionalData: self.additionalData, ephKeyName: self.ephPrivateKeyName, recipientCardId: self.recipientIdCard.identifier, recipientPublicKey: self.recipientIdCard.publicKeyData, recipientLongTermCardId: self.recipientLtCard.identifier, recipientLongTermPublicKey: self.recipientLtCard.publicKeyData, recipientOneTimeCardId: self.recipientOtCard.identifier, recipientOneTimePublicKey: self.recipientOtCard.publicKeyData)
            
            try self.sessionHelper.saveSessionState(sessionState, forRecipientCardId: self.recipientIdCard.identifier)
        }
    }
}
