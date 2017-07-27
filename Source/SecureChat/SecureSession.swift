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
    
    public var isInitialized: Bool {
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
    
    class func makeError(withCode code: SecureSessionErrorCode, description: String) -> NSError {
        return NSError(domain: SecureSession.ErrorDomain, code: code.rawValue, userInfo: [NSLocalizedDescriptionKey: description])
    }
}

extension SecureSession {
    public func isSessionExpired(relativelyToCurrentDate currentDate: Date) -> Bool {
        return currentDate > self.expirationDate
    }
    
    public var isExpired: Bool {
        return self.isSessionExpired(relativelyToCurrentDate: Date())
    }
}

extension SecureSession {
    func decrypt(encryptedMessage: Message) throws -> String {
        guard let message = VSCPfsEncryptedMessage(sessionIdentifier: encryptedMessage.sessionId, salt: encryptedMessage.salt, cipherText: encryptedMessage.cipherText) else {
            throw SecureSession.makeError(withCode: .convertingEncryptedMessageWhileDecrypting, description: "Error converting encrypted message while decrypting.")
        }
        
        guard let msgData = self.pfs.decryptMessage(message) else {
            throw SecureSession.makeError(withCode: .decryptingMessage, description: "Error decrypting message.")
        }
        
        guard let str = String(data: msgData, encoding: .utf8) else {
            throw SecureSession.makeError(withCode: .convertingDecrypytedMessageToString, description: "Error converting decrypted message to string.")
        }
        
        return str
    }
}

// Encryption
extension SecureSession {
    public func encrypt(_ message: String) throws -> String {
        guard let messageData = message.data(using: .utf8) else {
            throw SecureSession.makeError(withCode: .convertingMessageToDataWhileEncrypting, description: "Error converting message to data while encrypting.")
        }
        
        guard let encryptedMessage = self.pfs.encryptData(messageData) else {
            throw SecureSession.makeError(withCode: .encryptingMessage, description: "Error encrypting message.")
        }
        
        let msg = Message(sessionId: encryptedMessage.sessionIdentifier, salt: encryptedMessage.salt, cipherText: encryptedMessage.cipherText)
        
        let msgData: Data
        do {
            msgData = try JSONSerialization.data(withJSONObject: msg.serialize(), options: [])
        }
        catch {
            throw SecureSession.makeError(withCode: .convertingEncryptedMessageToJson, description: "Error converting encrypted message to json. Underlying error: \(error.localizedDescription)")
        }
        
        guard let msgStr = String(data: msgData, encoding: .utf8) else {
            throw SecureSession.makeError(withCode: .convertingMessageToUtf8Data, description: "Error converting encrypted message to data using utf8.")
        }
        
        return msgStr
    }
    
    public func decrypt(_ encryptedMessage: String) throws -> String {
        throw SecureSession.makeError(withCode: .decryptShouldBeOverridden, description: "Decrypt should be overridden in subclasses")
    }
}

extension SecureSession {
    static func extractInitiationMessage(_ message: Data) throws -> InitiationMessage {
        let dict = try JSONSerialization.jsonObject(with: message, options: [])
        
        guard let msg = InitiationMessage(dictionary: dict) else {
            throw SecureSession.makeError(withCode: .extractingInitiationMessage, description: "Error while extracting initiation message.")
        }
        
        return msg
    }
    
    static func extractMessage(_ message: Data) throws -> Message {
        let dict = try JSONSerialization.jsonObject(with: message, options: [])
        
        guard let msg = Message(dictionary: dict) else {
            throw SecureSession.makeError(withCode: .extractingMessage, description: "Error while extracting message.")
        }
        
        return msg
    }
}
