//
//  KeyStorage.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

@objc(VSPKeyStorage) public class KeyStorage: NSObject, KeyStorageProtocol {
    private let keychainKeyStorage: VSSKeyStorage
    
    init(keychainKeyStorage: VSSKeyStorage) {
        self.keychainKeyStorage = keychainKeyStorage
        
        super.init()
    }
    
    public func store(_ keyEntry: KeyEntry) throws {
        try self.keychainKeyStorage.store(VSSKeyEntry(name: keyEntry.name, value: keyEntry.value))
    }
    
    public func update(_ keyEntry: KeyEntry) throws {
        try self.keychainKeyStorage.update(VSSKeyEntry(name: keyEntry.name, value: keyEntry.value))
    }
    
    public func loadKeyEntry(withName name: String) throws -> KeyEntry {
        let keychainEntry = try self.keychainKeyStorage.loadKeyEntry(withName: name)
        return KeyEntry(name: keychainEntry.name, value: keychainEntry.value)
    }
    
    public func existsKeyEntry(withName name: String) -> Bool {
        return self.keychainKeyStorage.existsKeyEntry(withName: name)
    }
    
    public func deleteKeyEntry(withName name: String) throws {
        try self.keychainKeyStorage.deleteKeyEntry(withName: name)
    }
    
    public func getAllKeysTags() throws -> [Data] {
        return try self.keychainKeyStorage.getAllKeysTags()
    }
}
