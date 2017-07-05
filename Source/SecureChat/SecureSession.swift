//
//  SecureSession.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/20/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK
import VirgilCrypto

@objc(VSPSecureSession) public class SecureSession: NSObject {
    struct CardEntry {
        let identifier: String
        let publicKeyData: Data
    }
    
    let crypto: VSSCryptoProtocol
    let myPrivateKey: VSSPrivateKey
    let wasRecovered: Bool
    let additionalData: Data?
    let sessionHelper: SecureChatSessionHelper
    let creationDate: Date
    let expirationDate: Date
    
    static public let ErrorDomain = "VSPSecureSessionErrorDomain"
    
    let pfs = VSCPfs()
    
    var isSessionInitialized: Bool {
        return self.pfs.session != nil
    }
    
    init(crypto: VSSCryptoProtocol, myPrivateKey: VSSPrivateKey, wasRecovered: Bool, sessionHelper: SecureChatSessionHelper, additionalData: Data?, creationDate: Date, expirationDate: Date) {
        self.crypto = crypto
        self.myPrivateKey = myPrivateKey
        self.wasRecovered = wasRecovered
        self.sessionHelper = sessionHelper
        self.additionalData = additionalData
        self.creationDate = creationDate
        self.expirationDate = expirationDate
        
        super.init()
    }
}

extension SecureSession {
    var isExpired: Bool {
        return Date() > self.expirationDate
    }
}

extension SecureSession {
    func decrypt(encryptedMessage: Message) throws -> String {
        guard let message = VSCPfsEncryptedMessage(sessionIdentifier: encryptedMessage.sessionId, salt: encryptedMessage.salt, cipherText: encryptedMessage.cipherText) else {
            throw NSError(domain: SecureSession.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error converting encrypted message while decrypting."])
        }
        
        guard let msgData = self.pfs.decryptMessage(message) else {
            throw NSError(domain: SecureSession.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error decrypting message."])
        }
        
        guard let str = String(data: msgData, encoding: .utf8) else {
            throw NSError(domain: SecureSession.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error converting decrypted message to string."])
        }
        
        return str
    }
}

// Encryption
extension SecureSession {
    public func encrypt(_ message: String) throws -> String {
        guard let messageData = message.data(using: .utf8) else {
            throw NSError(domain: SecureSession.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error converting decrypted message while encrypting."])
        }
        
        guard let encryptedMessage = self.pfs.encryptData(messageData) else {
            throw NSError(domain: SecureSession.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error encrypting message."])
        }
        
        let msg = Message(sessionId: encryptedMessage.sessionIdentifier, salt: encryptedMessage.salt, cipherText: encryptedMessage.cipherText)
        
        let msgData: Data
        do {
            msgData = try JSONSerialization.data(withJSONObject: msg.serialize(), options: [])
        }
        catch {
            throw NSError(domain: SecureSession.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error converting encrypted message to json."])
        }
        
        guard let msgStr = String(data: msgData, encoding: .utf8) else {
            throw NSError(domain: SecureSession.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error converting message to data using utf8."])
        }
        
        return msgStr
    }
    
    public func decrypt(_ encryptedMessage: String) throws -> String {
        throw NSError(domain: SecureSession.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Decrypt should be overrided in subclasses"])
    }
}

extension SecureSession {
    static func extractInitiationMessage(_ message: Data) throws -> InitiationMessage {
        let dict = try JSONSerialization.jsonObject(with: message, options: [])
        
        guard let msg = InitiationMessage(dictionary: dict) else {
            throw NSError(domain: SecureSession.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while extracting initiation message."])
        }
        
        return msg
    }
    
    static func extractMessage(_ message: Data) throws -> Message {
        let dict = try JSONSerialization.jsonObject(with: message, options: [])
        
        guard let msg = Message(dictionary: dict) else {
            throw NSError(domain: SecureSession.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while extracting message."])
        }
        
        return msg
    }
}
