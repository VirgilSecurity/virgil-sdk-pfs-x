//
//  KeychainKeyStorage.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

/// KeyStorage implementation that uses Keychain to store keys. Implemented using VSSKeyStorage from VirgilSDK under the hood
@objc(VSPKeychainKeyStorage) public class KeychainKeyStorage: NSObject, KeyStorage {
    private let virgilKeyStorage: VSSKeyStorage
    
    /// Convenience intializer
    convenience public override init() {
        self.init(virgilKeyStorage: VSSKeyStorage())
    }
    
    /// Initializer
    ///
    /// - Parameter virgilKeyStorage: configured VSSKeyStorage from VirgilSDK
    @objc public init(virgilKeyStorage: VSSKeyStorage) {
        self.virgilKeyStorage = virgilKeyStorage
        
        super.init()
    }
    
    /// Stores key entry
    ///
    /// - Parameter keyEntry: Key entry
    /// - Throws: NSError instances with corresponding description
    public func storeKeyEntry(_ keyEntry: KeyEntry) throws {
        Log.debug("Storing key entry: \(keyEntry.name)")
        
        try self.virgilKeyStorage.store(VSSKeyEntry(name: keyEntry.name, value: keyEntry.value))
    }
    
    /// Stores muplitple key entries
    ///
    /// - Parameter keyEntries: key entries to store
    /// - Throws: NSError instances with corresponding description
    public func storeKeyEntries(_ keyEntries: [KeyEntry]) throws {
        Log.debug("Storing key entries: \(keyEntries.map({ $0.name }))")
        
        try self.virgilKeyStorage.storeKeyEntries(keyEntries.map({ VSSKeyEntry(name: $0.name, value: $0.value) }))
    }
    
    /// Loads key entry
    ///
    /// - Parameter name: key entry name
    /// - Returns: loaded key entry
    /// - Throws: NSError instances with corresponding description
    public func loadKeyEntry(withName name: String) throws -> KeyEntry {
        Log.debug("Loading key entry: \(name)")
        
        let keychainEntry = try self.virgilKeyStorage.loadKeyEntry(withName: name)
        return KeyEntry(name: keychainEntry.name, value: keychainEntry.value)
    }
    
    /// Deletes key entry
    ///
    /// - Parameter name: key entry name
    /// - Throws: NSError instances with corresponding description
    public func deleteKeyEntry(withName name: String) throws {
        Log.debug("Deleting key entry: \(name)")
        
        try self.virgilKeyStorage.deleteKeyEntry(withName: name)
    }
    
    /// Deletes multiple key entries
    ///
    /// - Parameter names: key entries names
    /// - Throws: NSError instances with corresponding description
    public func deleteKeyEntries(withNames names: [String]) throws {
        Log.debug("Deleting key entries: \(names)")
        
        try self.virgilKeyStorage.deleteKeyEntries(withNames: names)
    }
    
    /// Returns all keys attributes
    ///
    /// - Returns: all keys attributes
    /// - Throws: NSError instances with corresponding description
    public func getAllKeysAttrs() throws -> [KeyAttrs] {
        Log.debug("Getting all keys attrs")
        
        return try self.virgilKeyStorage.getAllKeysAttrs().map({ KeyAttrs(name: $0.name, creationDate: $0.creationDate) })
    }
}
