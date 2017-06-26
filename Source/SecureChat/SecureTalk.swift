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
    struct CardEntry {
        let identifier: String
        let publicKeyData: Data
    }
    
    public let crypto: VSSCryptoProtocol
    public let myPrivateKey: VSSPrivateKey
    public let wasRecovered: Bool
    
    static public let ErrorDomain = "VSPSecureTalkErrorDomain"
    
    let pfs = VSCPfs()
    
    var isSessionInitialized: Bool {
        return self.pfs.session != nil
    }
    
    // For initiator
    init(crypto: VSSCryptoProtocol, myPrivateKey: VSSPrivateKey, wasRecovered: Bool) {
        self.crypto = crypto
        self.myPrivateKey = myPrivateKey
        self.wasRecovered = wasRecovered
        
        super.init()
    }
}

extension SecureTalk {
    func decrypt(encryptedMessage: Message) throws -> String {
        guard let message = VSCPfsEncryptedMessage(sessionIdentifier: encryptedMessage.sessionId, salt: encryptedMessage.salt, cipherText: encryptedMessage.cipherText) else {
            throw NSError()
        }
        
        guard let msgData = self.pfs.decryptMessage(message) else {
            throw NSError()
        }
        
        guard let str = String(data: msgData, encoding: .utf8) else {
            throw NSError()
        }
        
        return str
    }
}

// Encryption
extension SecureTalk {
    public func encrypt(_ message: String) throws -> Data {
        guard let messageData = message.data(using: .utf8) else {
            throw NSError()
        }
        
        guard let encryptedMessage = self.pfs.encryptData(messageData) else {
            // FIXME
            throw NSError()
        }
        
        // FIXME: Add support for weak sessions
        let msg = Message(sessionId: encryptedMessage.sessionIdentifier, salt: encryptedMessage.salt, cipherText: encryptedMessage.cipherText)
        let msgData = try JSONSerialization.data(withJSONObject: msg.serialize(), options: [])
        return msgData
    }
    
    public func decrypt(_ encryptedMessage: Data) throws -> String {
        let msg = try SecureTalk.extractMessage(encryptedMessage)
        
        return try self.decrypt(encryptedMessage: msg)
    }
}

extension SecureTalk {
    static func extractInitiationMessage(_ message: Data) throws -> InitiationMessage {
        let dict = try JSONSerialization.jsonObject(with: message, options: [])
        
        guard let msg = InitiationMessage(dictionary: dict) else {
            throw NSError()
        }
        
        return msg
    }
    
    static func extractMessage(_ message: Data) throws -> Message {
        let dict = try JSONSerialization.jsonObject(with: message, options: [])
        
        guard let msg = Message(dictionary: dict) else {
            throw NSError()
        }
        
        return msg
    }
}
