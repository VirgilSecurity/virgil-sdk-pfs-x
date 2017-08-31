//
//  MigrationManager.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/31/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

class MigrationManager {
    let crypto: VSSCryptoProtocol
    let identityPrivateKey: VSSPrivateKey
    let identityCard: VSSCard
    let keyStorage: KeyStorage
    let keyStorageManager: KeyStorageManager
    let storage: InsensitiveDataStorage
    let sessionInitializer: SessionInitializer
    let sessionManager: SessionManager
    let defaultsClassType: UserDefaultsProtocol.Type
    
    init(crypto: VSSCryptoProtocol, identityPrivateKey: VSSPrivateKey, identityCard: VSSCard, keyStorage: KeyStorage, keyStorageManager: KeyStorageManager, storage: InsensitiveDataStorage, sessionInitializer: SessionInitializer, sessionManager: SessionManager, defaultsClassType: UserDefaultsProtocol.Type = UserDefaults.self) {
        self.crypto = crypto
        self.identityPrivateKey = identityPrivateKey
        self.identityCard = identityCard
        self.keyStorage = keyStorage
        self.keyStorageManager = keyStorageManager
        self.storage = storage
        self.sessionInitializer = sessionInitializer
        self.sessionManager = sessionManager
        self.defaultsClassType = defaultsClassType
    }
    
    func migrateToV1_1() throws {
        Log.debug("Migrating to 1.1")
        
        let migration = try MigrationV1_1(crypto: self.crypto, identityPrivateKey: self.identityPrivateKey, identityCard: self.identityCard, keyStorage: self.keyStorage, keyStorageManager: self.keyStorageManager, storage: self.storage, sessionInitializer: self.sessionInitializer, sessionManager: self.sessionManager)
        
        try migration.migrate()
    }
}
