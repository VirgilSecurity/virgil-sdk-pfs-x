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
    public let myIdCard: VSSCard
    public let ephPrivateKey: VSSPrivateKey
    public let recipientIdCard: CardEntry
    public let recipientLtCard: CardEntry
    public let recipientOtCard: CardEntry
    
    init(crypto: VSSCryptoProtocol, myPrivateKey: VSSPrivateKey, myIdCard: VSSCard, ephPrivateKey: VSSPrivateKey, recipientIdCard: CardEntry, recipientLtCard: CardEntry, recipientOtCard: CardEntry, wasRecovered: Bool) throws {
        self.myIdCard = myIdCard
        self.ephPrivateKey = ephPrivateKey
        self.recipientIdCard = recipientIdCard
        self.recipientLtCard = recipientLtCard
        self.recipientOtCard = recipientOtCard
        
        super.init(crypto: crypto, myPrivateKey: myPrivateKey, wasRecovered: wasRecovered)
        
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
            throw NSError()
        }
        
        if isFirstMessage {
            guard let messageData = message.data(using: .utf8) else {
                throw NSError()
            }
            
            guard let encryptedMessage = self.pfs.encryptData(messageData) else {
                // FIXME
                throw NSError()
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
            throw NSError()
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
                throw NSError()
        }
        
        guard let initiatorPrivateInfo = VSCPfsInitiatorPrivateInfo(identityPrivateKey: privateKey, ephemeralPrivateKey: ephPrivateKey) else {
            throw NSError()
        }
        
        let responderPublicKeyData = self.recipientIdCard.publicKeyData
        let responderLongTermPublicKeyData = self.recipientLtCard.publicKeyData
        let responderOneTimePublicKeyData = self.recipientOtCard.publicKeyData
        guard let responderPublicKey = VSCPfsPublicKey(key: responderPublicKeyData),
            let responderLongTermPublicKey = VSCPfsPublicKey(key: responderLongTermPublicKeyData),
            let responderOneTimePublicKey = VSCPfsPublicKey(key: responderOneTimePublicKeyData) else {
                throw NSError()
        }
        
        guard let responderPublicInfo = VSCPfsResponderPublicInfo(identityPublicKey: responderPublicKey, longTermPublicKey: responderLongTermPublicKey, oneTime: responderOneTimePublicKey) else {
            throw NSError()
        }
        
        // FIXME
        guard let _ = self.pfs.startInitiatorSession(with: initiatorPrivateInfo, respondrerPublicInfo: responderPublicInfo, additionalData: nil) else {
            throw NSError()
        }
    }
}
