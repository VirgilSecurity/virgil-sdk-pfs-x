//
//  SecureTalkResponder.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK
import VirgilCrypto

class SecureTalkResponder: SecureTalk {
    public let secureChatKeyHelper: SecureChatKeyHelper
    public let initiatorIdCard: VSSCard
    
    init(crypto: VSSCryptoProtocol, myPrivateKey: VSSPrivateKey, secureChatKeyHelper: SecureChatKeyHelper, initiatorIdCard: VSSCard) {
        self.secureChatKeyHelper = secureChatKeyHelper
        self.initiatorIdCard = initiatorIdCard
        
        super.init(crypto: crypto, myPrivateKey: myPrivateKey)
    }
}

// Encryption
extension SecureTalkResponder {
    override func encrypt(_ message: String) throws -> Data {
        guard self.isSessionInitialized else {
            throw NSError()
        }
        
        return try super.encrypt(message)
    }
    
    override func decrypt(_ encryptedMessage: Data) throws -> String {
        if !self.isSessionInitialized {
            let dict = try JSONSerialization.jsonObject(with: encryptedMessage, options: [])
            
            guard let msg = InitiationMessage(dictionary: dict) else {
                throw NSError()
            }
            
            try self.initiateSession(withInitiationMessage: msg)
            
            guard self.isSessionInitialized else {
                throw NSError()
            }
            
            guard let sessionId = self.pfs.session?.identifier else {
                throw NSError()
            }
            
            // FIXME: Weak sessions
            let message = Message(sessionId: sessionId, salt: msg.strongSessionData.salt, cipherText: msg.strongSessionData.cipherText)
            
            return try self.decrypt(encryptedMessage: message)
        }
        else {
            guard self.isSessionInitialized else {
                throw NSError()
            }
            
            return try super.decrypt(encryptedMessage)
        }
    }
}

// Session initialization
extension SecureTalkResponder {
    fileprivate func initiateSession(withInitiationMessage initiationMessage: InitiationMessage) throws {
        // Check signature
        guard initiationMessage.initiatorIcId == self.initiatorIdCard.identifier else {
            throw NSError(domain: SecureTalk.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Initiator identity card id for this talk and InitiationMessage doesn't match."])
        }
        
        let privateKeyData = self.crypto.export(self.myPrivateKey, withPassword: nil)
        
        let myLtPrivateKey = try self.secureChatKeyHelper.getLtPrivateKey(keyName: initiationMessage.receiverLtcId)
        let myOtPrivateKey = try self.secureChatKeyHelper.getOtPrivateKey(keyName: initiationMessage.strongSessionData.receiverOtcId)
        
        let ltPrivateKeyData = self.crypto.export(myLtPrivateKey, withPassword: nil)
        // FIXME: Weak sessions
        let otPrivateKeyData = self.crypto.export(myOtPrivateKey, withPassword: nil)
        guard let privateKey = VSCPfsPrivateKey(key: privateKeyData, password: nil),
            let ltPrivateKey = VSCPfsPrivateKey(key: ltPrivateKeyData, password: nil),
            let otPrivateKey = VSCPfsPrivateKey(key: otPrivateKeyData, password: nil) else {
                throw NSError()
        }
        
        guard let responderPrivateInfo = VSCPfsResponderPrivateInfo(identityPrivateKey: privateKey, longTermPrivateKey: ltPrivateKey, oneTime: otPrivateKey) else {
            throw NSError()
        }
        
        guard let initiatorEphPublicKey = VSCPfsPublicKey(key: initiationMessage.ephPublicKey),
            let initiatorIdPublicKey = VSCPfsPublicKey(key: self.initiatorIdCard.publicKeyData) else {
                throw NSError()
        }
        
        guard let responderPublicInfo = VSCPfsInitiatorPublicInfo(identityPublicKey: initiatorIdPublicKey, ephemeralPublicKey: initiatorEphPublicKey) else {
            throw NSError()
        }
        
        // FIXME
        guard let _ = self.pfs.startResponderSession(with: responderPrivateInfo, respondrerPublicInfo: responderPublicInfo, additionalData: nil) else {
            throw NSError()
        }
    }
}
