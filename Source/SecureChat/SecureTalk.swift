//
//  SecureTalk.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/20/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK
import VirgilCrypto

@objc(VSPSecureTalk) public class SecureTalk: NSObject {
    public let crypto: VSSCryptoProtocol
    public let myIdCard: VSSCard
    public let myPrivateKey: VSSPrivateKey
    public let ephPrivateKey: VSSPrivateKey
    public let recipientIdCard: VSSCard
    public let recipientLtCard: VSSCard
    public let recipientOtCard: VSSCard
    
    fileprivate let pfs = VSCPfs()
    
    fileprivate var isSessionInitialized: Bool {
        return self.pfs.session != nil
    }
    
    init(crypto: VSSCryptoProtocol, myIdCard: VSSCard, myPrivateKey: VSSPrivateKey, ephPrivateKey: VSSPrivateKey, recipientIdCard: VSSCard, recipientLtCard: VSSCard, recipientOtCard: VSSCard) {
        self.crypto = crypto
        self.myIdCard = myIdCard
        self.myPrivateKey = myPrivateKey
        self.ephPrivateKey = ephPrivateKey
        self.recipientIdCard = recipientIdCard
        self.recipientLtCard = recipientLtCard
        self.recipientOtCard = recipientOtCard
        
        super.init()
    }
}

// Encryption
extension SecureTalk {
    func encrypt(message: String) throws -> Data {
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
        
        guard let messageData = message.data(using: .utf8) else {
            throw NSError()
        }
        
        guard let encryptedMessage = self.pfs.encryptData(messageData) else {
            // FIXME
            throw NSError()
        }
        
        if isFirstMessage {
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
            let msg = Message(sessionId: encryptedMessage.sessionIdentifier, salt: encryptedMessage.salt, cipherText: encryptedMessage.cipherText)
            let msgData = try JSONSerialization.data(withJSONObject: msg.serialize(), options: [])
            return msgData
        }
    }
    
    func decrypt(encryptedMessage: String) -> String {
        // FIXME
        return ""
    }
}

// Session initialization
extension SecureTalk {
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
