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
    
    static public let ErrorDomain = "VSPSecureTalkErrorDomain"
    
    let pfs = VSCPfs()
    
    var isSessionInitialized: Bool {
        return self.pfs.session != nil
    }
    
    // For initiator
    init(crypto: VSSCryptoProtocol, myPrivateKey: VSSPrivateKey) {
        self.crypto = crypto
        self.myPrivateKey = myPrivateKey
        
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
        let dict = try JSONSerialization.jsonObject(with: encryptedMessage, options: [])
        
        guard let msg = Message(dictionary: dict) else {
            throw NSError()
        }
        
        return try self.decrypt(encryptedMessage: msg)
    }
}
