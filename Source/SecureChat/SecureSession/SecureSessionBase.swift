//
//  SecureSessionBase.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCrypto

@objc(VSPSecureSessionBase) public class SecureSessionBase: SecureSession {
    let crypto: VSSCryptoProtocol
    let myPrivateKey: VSSPrivateKey
    let participantCardId: String
    let wasRecovered: Bool
    let additionalData: Data?
    let sessionHelper: SecureChatSessionHelper
    let keyHelper: SecureChatKeyHelper
    let creationDate: Date
    
    
    init(crypto: VSSCryptoProtocol, myPrivateKey: VSSPrivateKey, participantCardId: String, wasRecovered: Bool, sessionHelper: SecureChatSessionHelper, keyHelper: SecureChatKeyHelper, additionalData: Data?, creationDate: Date, expirationDate: Date) {
        self.crypto = crypto
        self.myPrivateKey = myPrivateKey
        self.participantCardId = participantCardId
        self.wasRecovered = wasRecovered
        self.sessionHelper = sessionHelper
        self.keyHelper = keyHelper
        self.additionalData = additionalData
        self.creationDate = creationDate
        
        super.init(expirationDate: expirationDate)
    }
    
    func saveSession(_ session: VSCPfsSession) throws {
        let sessionId = session.identifier
        let encryptionKey = session.encryptionSecretKey
        let decryptionKey = session.decryptionSecretKey
        let sessionKeys = SecureChatKeyHelper.SessionKeys(encryptionKey: encryptionKey, decryptionKey: decryptionKey)
        
        try self.keyHelper.saveSessionKeys(sessionKeys, forSessionWithId: sessionId)
        
        let sessionState = SessionState(creationDate: self.creationDate, expirationDate: self.expirationDate, sessionId: session.identifier, additionalData: session.additionalData)
        
        try self.sessionHelper.saveSessionState(sessionState, forRecipientCardId: self.participantCardId)
    }
}
