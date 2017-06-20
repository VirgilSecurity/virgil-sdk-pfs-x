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
    public let myPrivateKey: VSSPrivateKey
    public let ephPrivateKey: VSSPrivateKey
    public let recipientPublicKey: VSSPublicKey
    public let recipientLongTermKey: VSSPublicKey
    public let recipientOneTimeKey: VSSPublicKey?
    
    fileprivate let pfs = VSCPfs()
    
    fileprivate var isSessionInitialized: Bool {
        return self.pfs.session != nil
    }
    
    init(crypto: VSSCryptoProtocol, myPrivateKey: VSSPrivateKey, ephPrivateKey: VSSPrivateKey, recipientPublicKey: VSSPublicKey, recipientLongTermKey: VSSPublicKey, recipientOneTimeKey: VSSPublicKey? = nil) {
        self.crypto = crypto
        self.myPrivateKey = myPrivateKey
        self.ephPrivateKey = ephPrivateKey
        self.recipientPublicKey = recipientPublicKey
        self.recipientLongTermKey = recipientLongTermKey
        self.recipientOneTimeKey = recipientOneTimeKey
        
        super.init()
    }
}

// Encryption
extension SecureTalk {
    func encrypt(message: String) throws -> String {
        if !self.isSessionInitialized {
            try self.initiateSession()
        }
        
        guard self.isSessionInitialized else {
            throw NSError()
        }
        
        // FIXME
        return ""
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
        
        let responderPublicKeyData = self.crypto.export(self.recipientPublicKey)
        let responderLongTermPublicKeyData = self.crypto.export(self.recipientLongTermKey)
        guard let responderPublicKey = VSCPfsPublicKey(key: responderPublicKeyData),
            let responderLongTermPublicKey = VSCPfsPublicKey(key: responderLongTermPublicKeyData) else {
                throw NSError()
        }
        
        let responderOneTimeKey: VSCPfsPublicKey?
        if let rOneTimeKey = self.recipientOneTimeKey {
            let recipientOneTimePublicKeyData = self.crypto.export(rOneTimeKey)
            
            guard let recipientOneTimePublicKey = VSCPfsPublicKey(key: recipientOneTimePublicKeyData) else {
                throw NSError()
            }
            responderOneTimeKey = recipientOneTimePublicKey
        }
        else {
            responderOneTimeKey = nil
        }
        
        guard let responderPublicInfo = VSCPfsResponderPublicInfo(identityPublicKey: responderPublicKey, longTermPublicKey: responderLongTermPublicKey, oneTime: responderOneTimeKey) else {
            throw NSError()
        }
        
        // FIXME
        guard let _ = self.pfs.startInitiatorSession(with: initiatorPrivateInfo, respondrerPublicInfo: responderPublicInfo, additionalData: nil) else {
            throw NSError()
        }
    }
}
