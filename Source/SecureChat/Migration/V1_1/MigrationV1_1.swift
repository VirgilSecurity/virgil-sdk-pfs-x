//
//  MigrationV1_1.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/31/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

class MigrationV1_1 {
    let crypto: VSSCryptoProtocol
    let identityPrivateKey: VSSPrivateKey
    let identityCard: VSSCard
    let keyStorage: KeyStorage
    let keyStorageManager: KeyStorageManager
    let storage: InsensitiveDataStorage
    let sessionInitializer: SessionInitializer
    let sessionManager: SessionManager
    let userDefaults: UserDefaultsProtocol
    
    init(crypto: VSSCryptoProtocol, identityPrivateKey: VSSPrivateKey, identityCard: VSSCard, keyStorage: KeyStorage, keyStorageManager: KeyStorageManager, storage: InsensitiveDataStorage, sessionInitializer: SessionInitializer, sessionManager: SessionManager, defaultsClassType: UserDefaultsProtocol.Type = UserDefaults.self) throws {
        self.crypto = crypto
        self.identityPrivateKey = identityPrivateKey
        self.identityCard = identityCard
        self.keyStorage = keyStorage
        self.keyStorageManager = keyStorageManager
        self.storage = storage
        self.sessionInitializer = sessionInitializer
        self.sessionManager = sessionManager
        guard let userDefaults = defaultsClassType.init(suiteName: MigrationV1_1.getSuiteName(cardId: identityCard.identifier)) else {
            throw SecureChat.makeError(withCode: .migrationV1_1InvalidDefaults, description: "Error initializing UserDefaults while migrating to 1.1.")
        }
        
        self.userDefaults = userDefaults
    }
    
    class func getSuiteName(cardId: String) -> String {
        return "VIRGIL.DEFAULTS.\(cardId)"
    }
    
    func migrate() throws {
        // Get sessions
        let (initiators, responders) = try self.getAllSessions()
        
        // Migrate initiator's sessions
        for initiator in initiators {
            let ephKeyName = initiator.value.ephKeyName
            let ephKeyEntry = try self.getEphPrivateKey(name: ephKeyName)
            guard let ephPrivateKey = self.crypto.importPrivateKey(from: ephKeyEntry.value) else {
                throw SecureChat.makeError(withCode: .migrationV1_1ImportingEphPrivateKey, description: "Error importing Eph private key while migrating to 1.1.")
            }
            
            let recipientIdCard = CardEntry(identifier: initiator.value.recipientCardId, publicKeyData: initiator.value.recipientPublicKey)
            let recipientLtCard = CardEntry(identifier: initiator.value.recipientLongTermCardId, publicKeyData: initiator.value.recipientLongTermPublicKey)
            
            let recipientOtCard: CardEntry?
            if let recOtCardId = initiator.value.recipientOneTimeCardId,
                let recOtPubKey = initiator.value.recipientOneTimePublicKey {
                    recipientOtCard = CardEntry(identifier: recOtCardId, publicKeyData: recOtPubKey)
            }
            else {
                recipientOtCard = nil
            }
            
            let secureSession = try self.sessionInitializer.initializeInitiatorSession(ephPrivateKey: ephPrivateKey, recipientIdCard: recipientIdCard, recipientLtCard: recipientLtCard, recipientOtCard: recipientOtCard, additionalData: initiator.value.additionalData, expirationDate: initiator.value.expirationDate)
            
            try self.sessionManager.saveSession(secureSession, creationDate: initiator.value.creationDate, participantCardId: recipientIdCard.identifier)
            
            try self.removeEphPrivateKey(name: ephKeyName)
        }
        
        // Migrate responder's sessions
        for responder in responders {
            let ltPrivateKey = try self.keyStorageManager.getLtPrivateKey(withName: responder.value.recipientLongTermCardId)
            
            let otPrivateKey: VSSPrivateKey?
            if let recOtId = responder.value.recipientOneTimeCardId {
                otPrivateKey = try self.keyStorageManager.getOtPrivateKey(withName: recOtId)
            }
            else {
                otPrivateKey = nil
            }
            
            let initiatorCardEntry = CardEntry(identifier: responder.value.recipientIdentityCardId, publicKeyData: responder.value.recipientIdentityPublicKey)
            
            let secureSession = try self.sessionInitializer.initializeResponderSession(initiatorCardEntry: initiatorCardEntry, privateKey: self.identityPrivateKey, ltPrivateKey: ltPrivateKey, otPrivateKey: otPrivateKey, ephPublicKey: responder.value.ephPublicKeyData, additionalData: responder.value.additionalData, expirationDate: responder.value.expirationDate)
            
            try self.sessionManager.saveSession(secureSession, creationDate: responder.value.creationDate, participantCardId: initiatorCardEntry.identifier)
            
            if let recOtId = responder.value.recipientOneTimeCardId {
                try self.keyStorageManager.removeOtPrivateKey(withName: recOtId)
            }
        }
        
        // Remove Service info
        try? self.removeServiceInfoEntry()
        
        // Remove old session
        try self.removeAllSessions()
    }
}
