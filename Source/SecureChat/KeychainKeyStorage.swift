//
//  KeychainKeyStorage.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

@objc(VSPKeychainKeyStorage) public class KeychainKeyStorage: NSObject, KeyStorage {
    private let virgilKeyStorage: VSSKeyStorage
    
    init(virgilKeyStorage: VSSKeyStorage) {
        self.virgilKeyStorage = virgilKeyStorage
        
        super.init()
    }
    
    public func storeKeyEntry(_ keyEntry: KeyEntry) throws {
        try self.virgilKeyStorage.store(VSSKeyEntry(name: keyEntry.name, value: keyEntry.value))
    }
    
    public func storeKeyEntries(_ keyEntries: [KeyEntry]) throws {
        try self.virgilKeyStorage.storeKeyEntries(keyEntries.map({ VSSKeyEntry(name: $0.name, value: $0.value) }))
    }
    
    public func updateKeyEntry(_ keyEntry: KeyEntry) throws {
        try self.virgilKeyStorage.update(VSSKeyEntry(name: keyEntry.name, value: keyEntry.value))
    }
    
    public func loadKeyEntry(withName name: String) throws -> KeyEntry {
        let keychainEntry = try self.virgilKeyStorage.loadKeyEntry(withName: name)
        return KeyEntry(name: keychainEntry.name, value: keychainEntry.value)
    }
    
    public func existsKeyEntry(withName name: String) -> Bool {
        return self.virgilKeyStorage.existsKeyEntry(withName: name)
    }
    
    public func deleteKeyEntry(withName name: String) throws {
        try self.virgilKeyStorage.deleteKeyEntry(withName: name)
    }
    
    public func deleteKeyEntries(withNames names: [String]) throws {
        try self.virgilKeyStorage.deleteKeyEntries(withNames: names)
    }
    
    public func getAllKeysTags() throws -> [Data] {
        return try self.virgilKeyStorage.getAllKeysTags()
    }
}
