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

/// Class used to represent Secure Pfs Session between paticipants
@objc(VSPSecureSession) public class SecureSession: NSObject {
    /// Error domain for NSError instances thrown from here
    @objc static public let ErrorDomain = "VSPSecureSessionErrorDomain"
    
    let expirationDate: Date
    
    fileprivate var firstMsgGenerator: ((SecureSession, String) throws -> String)?
    
    fileprivate let pfs = VSCPfs()
    private let pfsSession: VSCPfsSession
    
    /// Session identifier
    @objc public var identifier: Data { return self.pfsSession.identifier }
    var encryptionKey: Data { return self.pfsSession.encryptionSecretKey }
    var decryptionKey: Data { return self.pfsSession.decryptionSecretKey }
    var additionalData: Data { return self.pfsSession.additionalData }
    
    init(pfsSession: VSCPfsSession, expirationDate: Date, firstMsgGenerator: ((SecureSession, String) throws -> String)?) {
        self.pfsSession = pfsSession
        self.pfs.session = pfsSession
        self.expirationDate = expirationDate
        self.firstMsgGenerator = firstMsgGenerator
        
        super.init()
    }
    
    class func makeError(withCode code: SecureSessionErrorCode, description: String) -> NSError {
        return NSError(domain: SecureSession.ErrorDomain, code: code.rawValue, userInfo: [NSLocalizedDescriptionKey: description])
    }
}

// MARK: - isExpired
extension SecureSession {
    /// Checks if this session is expired
    ///
    /// - Parameter now: current date
    /// - Returns: true if sesion is expired, false otherwise
    @objc public func isExpired(now: Date) -> Bool {
        return now > self.expirationDate
    }
}

// MARK: - Decryption
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
    
    /// Decrypts message
    ///
    /// - Parameter encryptedMessage: encrypted message
    /// - Returns: decrypted message
    /// - Throws: NSError instances with corresponding description
    @objc public func decrypt(_ encryptedMessage: String) throws -> String {
        guard let messageData = encryptedMessage.data(using: .utf8) else {
            throw SecureSession.makeError(withCode: .convertingMessageToUtf8Data, description: "Error while converting message to data in SecureSession.")
        }
        
        let message: Message
        if let initiationMessage = try? SecureSession.extractInitiationMessage(fromData: messageData),
            let pfsSession = self.pfs.session {
            message = Message(sessionId: pfsSession.identifier, salt: initiationMessage.salt, cipherText: initiationMessage.cipherText)
        }
        else {
            guard let msg = try? SecureSession.extractMessage(fromData: messageData) else {
                throw SecureSession.makeError(withCode: .extractingMessage, description: "Error while extracting message in SecureSession.")
            }
            message = msg
        }
        
        return try self.decrypt(encryptedMessage: message)
    }
}

// MARK: - Encryption
extension SecureSession {
    /// Encrypts message
    ///
    /// - Parameter message: message to encrypt
    /// - Returns: encrypted message
    /// - Throws: NSError instances with corresponding description
    @objc public func encrypt(_ message: String) throws -> String {
        // Initiation message
        if let firstMsgGenerator = self.firstMsgGenerator {
            let encryptedMessage = try firstMsgGenerator(self, message)
            self.firstMsgGenerator = nil
            return encryptedMessage
        }
        
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
}

extension SecureSession {
    @objc func encryptInitiationMessage(_ message: String, ephPublicKeyData: Data, ephPublicKeySignature: Data, initiatorIcId: String, responderIcId: String, responderLtcId: String, responderOtcId: String?) throws -> String {
        guard let messageData = message.data(using: .utf8) else {
            throw SecureSession.makeError(withCode: .convertingMessageToDataWhileEncrypting, description: "Error converting message to data while encrypting.")
        }
        
        guard let encryptedMessage = self.pfs.encryptData(messageData) else {
            throw SecureSession.makeError(withCode: .encryptingMessage, description: "Error encrypting message.")
        }
        
        let initMsg = InitiationMessage(initiatorIcId: initiatorIcId, responderIcId: responderIcId, responderLtcId: responderLtcId, responderOtcId: responderOtcId, ephPublicKey: ephPublicKeyData, ephPublicKeySignature: ephPublicKeySignature, salt: encryptedMessage.salt, cipherText: encryptedMessage.cipherText)
        
        let msgData = try JSONSerialization.data(withJSONObject: initMsg.serialize(), options: [])
        
        guard let msgStr = String(data: msgData, encoding: .utf8) else {
            throw SecureSession.makeError(withCode: .convertingEncryptedInitiationMessageToUtf8Data, description: "Error converting encrypted initiation message to data using utf8.")
        }
        
        return msgStr
    }
}

extension SecureSession {
    static func extractInitiationMessage(fromData data: Data) throws -> InitiationMessage {
        let dict = try JSONSerialization.jsonObject(with: data, options: [])
        
        guard let msg = InitiationMessage(dictionary: dict) else {
            throw SecureSession.makeError(withCode: .extractingInitiationMessage, description: "Error while extracting initiation message.")
        }
        
        return msg
    }
    
    static func extractMessage(fromData data: Data) throws -> Message {
        let dict = try JSONSerialization.jsonObject(with: data, options: [])
        
        guard let msg = Message(dictionary: dict) else {
            throw SecureSession.makeError(withCode: .extractingMessage, description: "Error while extracting message.")
        }
        
        return msg
    }
}

extension SecureSession {
    public override func isEqual(_ object: Any?) -> Bool {
        guard let other = object as? SecureSession else {
            return false
        }
        
        return self.additionalData == other.additionalData
            && self.decryptionKey == other.decryptionKey
            && self.encryptionKey == other.encryptionKey
            && self.expirationDate == other.expirationDate
            && self.identifier == other.identifier
    }
}
