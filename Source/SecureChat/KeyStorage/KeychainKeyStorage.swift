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
        Log.debug("Storing key entry: \(keyEntry.name)")
        
        try self.virgilKeyStorage.store(VSSKeyEntry(name: keyEntry.name, value: keyEntry.value))
    }
    
    public func storeKeyEntries(_ keyEntries: [KeyEntry]) throws {
        Log.debug("Storing key entries: \(keyEntries.map({ $0.name }))")
        
        try self.virgilKeyStorage.storeKeyEntries(keyEntries.map({ VSSKeyEntry(name: $0.name, value: $0.value) }))
    }
    
    public func updateKeyEntry(_ keyEntry: KeyEntry) throws {
        Log.debug("Updating key entry: \(keyEntry.name))")
        
        try self.virgilKeyStorage.update(VSSKeyEntry(name: keyEntry.name, value: keyEntry.value))
    }
    
    public func loadKeyEntry(withName name: String) throws -> KeyEntry {
        Log.debug("Loading key entry: \(name)")
        
        let keychainEntry = try self.virgilKeyStorage.loadKeyEntry(withName: name)
        return KeyEntry(name: keychainEntry.name, value: keychainEntry.value)
    }
    
    public func existsKeyEntry(withName name: String) -> Bool {
        Log.debug("Checking key entry existence: \(name)")
        
        return self.virgilKeyStorage.existsKeyEntry(withName: name)
    }
    
    public func deleteKeyEntry(withName name: String) throws {
        Log.debug("Deleting key entry: \(name)")
        
        try self.virgilKeyStorage.deleteKeyEntry(withName: name)
    }
    
    public func deleteKeyEntries(withNames names: [String]) throws {
        Log.debug("Deleting key entries: \(names)")
        
        try self.virgilKeyStorage.deleteKeyEntries(withNames: names)
    }
    
    public func getAllKeysAttrs() throws -> [KeyAttrs] {
        Log.debug("Getting all keys attrs")
        
        return try self.virgilKeyStorage.getAllKeysAttrs().map({ KeyAttrs(name: $0.name, creationDate: $0.creationDate) })
    }
}
