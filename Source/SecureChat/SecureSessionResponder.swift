//
//  SecureSessionResponder.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK
import VirgilCrypto

class SecureSessionResponder: SecureSession {
    public let secureChatKeyHelper: SecureChatKeyHelper
    public let initiatorIdCard: CardEntry
    
    init(crypto: VSSCryptoProtocol, myPrivateKey: VSSPrivateKey, sessionHelper: SecureChatSessionHelper, additionalData: Data?, secureChatKeyHelper: SecureChatKeyHelper, initiatorCardEntry: CardEntry, ephPublicKeyData: Data, receiverLtcId: String, receiverOtcId: String?, creationDate: Date, expirationDate: Date) throws {
        self.secureChatKeyHelper = secureChatKeyHelper
        self.initiatorIdCard = initiatorCardEntry
        
        super.init(crypto: crypto, myPrivateKey: myPrivateKey, wasRecovered: true, sessionHelper: sessionHelper, additionalData: additionalData, creationDate: creationDate, expirationDate: expirationDate)
        
        try self.initiateSession(ephPublicKeyData: ephPublicKeyData, receiverLtcId: receiverLtcId, receiverOtcId: receiverOtcId)
    }
    
    init(crypto: VSSCryptoProtocol, myPrivateKey: VSSPrivateKey, sessionHelper: SecureChatSessionHelper, additionalData: Data?, secureChatKeyHelper: SecureChatKeyHelper, initiatorCardEntry: CardEntry, creationDate: Date, expirationDate: Date) {
        self.initiatorIdCard = initiatorCardEntry
        self.secureChatKeyHelper = secureChatKeyHelper
        
        super.init(crypto: crypto, myPrivateKey: myPrivateKey, wasRecovered: false, sessionHelper: sessionHelper, additionalData: additionalData, creationDate: creationDate, expirationDate: expirationDate)
    }
}

// Encryption
extension SecureSessionResponder {
    override func encrypt(_ message: String) throws -> String {
        guard self.isInitialized else {
            throw SecureSession.makeError(withCode: .sessionStillNotInitializedWhileEncryptingInResponderSession, description: "Session is still not initialized while encrypting in responder session.")
        }
        
        return try super.encrypt(message)
    }
    
    func decrypt(_ initiationMessage: InitiationMessage) throws -> String {
        if !self.isInitialized {
            try self.initiateSession(withInitiationMessage: initiationMessage)
        }
        
        guard self.isInitialized else {
            throw SecureSession.makeError(withCode: .sessionStillNotInitializedWhileDecryptingInResponderSession, description: "Session is still not initialized while decrypting in responder session.")
        }
        
        guard let sessionId = self.pfs.session?.identifier else {
            throw SecureSession.makeError(withCode: .sessionIdIsMissing, description: "Session id is missing.")
        }
        
        let message = Message(sessionId: sessionId, salt: initiationMessage.salt, cipherText: initiationMessage.cipherText)
        
        return try self.decrypt(encryptedMessage: message)
    }
    
    override func decrypt(_ encryptedMessage: String) throws -> String {
        guard let messageData = encryptedMessage.data(using: .utf8) else {
            throw SecureSession.makeError(withCode: .convertingEncryptedMessageToDataWhileDecryptingInResponderSession, description: "Error converting encrypted message to data while decrypting in responder session.")
        }
        
        if let initiationMessage = try? SecureSessionResponder.extractInitiationMessage(messageData) {
            return try self.decrypt(initiationMessage)
        }
        else if let msg = try? SecureSession.extractMessage(messageData) {
            guard self.isInitialized else {
                throw SecureSession.makeError(withCode: .sessionStillNotInitializedWhileDecryptingInResponderSessionNotInitiationMessage, description: "Session is still not initialized while decrypting in responder session and got not initiation message.")
            }
            
            return try super.decrypt(encryptedMessage: msg)
        }
        else {
            throw SecureSession.makeError(withCode: .unknownMessageFormatWhileDecryptingInResponderSession, description: "Unknown message format while decrypting in responder session.")
        }
    }
}

// Session initialization
extension SecureSessionResponder {
    fileprivate func initiateSession(withInitiationMessage initiationMessage: InitiationMessage) throws {
        guard let initiatorPublicKey = self.crypto.importPublicKey(from: self.initiatorIdCard.publicKeyData) else {
            throw SecureSession.makeError(withCode: .importingInitiatorPublicKeyFromIdentityCard, description: "Error importing initiator public key from identity card.")
        }
        
        do {
            try self.crypto.verify(initiationMessage.ephPublicKey, withSignature: initiationMessage.ephPublicKeySignature, using: initiatorPublicKey)
        }
        catch {
            throw SecureSession.makeError(withCode: .validatingInitiatorSignature, description: "Error validating initiator signature.")
        }
        
        guard initiationMessage.initiatorIcId == self.initiatorIdCard.identifier else {
            throw SecureSession.makeError(withCode: .initiatorIdentityCardIdDoesntMatch, description: "Initiator identity card id for this session and InitiationMessage doesn't match.")
        }
        
        try self.initiateSession(ephPublicKeyData: initiationMessage.ephPublicKey, receiverLtcId: initiationMessage.responderLtcId, receiverOtcId: initiationMessage.responderOtcId)
    }
    
    fileprivate func initiateSession(ephPublicKeyData: Data, receiverLtcId: String, receiverOtcId: String?) throws {
        let privateKeyData = self.crypto.export(self.myPrivateKey, withPassword: nil)
        
        let myLtPrivateKey = try self.secureChatKeyHelper.getLtPrivateKey(withName: receiverLtcId)
        let myOtPrivateKey = receiverOtcId != nil ? try self.secureChatKeyHelper.getOtPrivateKey(name: receiverOtcId!) : nil
        
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
        
        guard let initiatorEphPublicKey = VSCPfsPublicKey(key: ephPublicKeyData),
            let initiatorIdPublicKey = VSCPfsPublicKey(key: self.initiatorIdCard.publicKeyData) else {
                throw SecureSession.makeError(withCode: .convertingInitiatorKeysDuringResponderInitialization, description: "Error while converting initiator crypto keys to pfs keys during responder initialization.")
        }
        
        guard let initiatorPublicInfo = VSCPfsInitiatorPublicInfo(identityPublicKey: initiatorIdPublicKey, ephemeralPublicKey: initiatorEphPublicKey) else {
            throw SecureSession.makeError(withCode: .instantiatingInitiatorPublicInfo, description: "Error instantiating initiatorPublicInfo.")
        }
        
        guard let session = self.pfs.startResponderSession(with: responderPrivateInfo, initiatorPublicInfo: initiatorPublicInfo, additionalData: self.additionalData) else {
            throw SecureSession.makeError(withCode: .initiatingResponderSession, description: "Error while initiating responder session.")
        }
        
        if !self.wasRecovered {
            let sessionId = session.identifier
            let session = ResponderSessionState(creationDate: self.creationDate, expirationDate: self.expirationDate, sessionId: sessionId, additionalData: self.additionalData, ephPublicKeyData: ephPublicKeyData, recipientIdentityCardId: self.initiatorIdCard.identifier, recipientIdentityPublicKey: self.initiatorIdCard.publicKeyData, recipientLongTermCardId: receiverLtcId, recipientOneTimeCardId: receiverOtcId)
            try self.sessionHelper.saveSessionState(session, forRecipientCardId: self.initiatorIdCard.identifier)
        }
    }
}
