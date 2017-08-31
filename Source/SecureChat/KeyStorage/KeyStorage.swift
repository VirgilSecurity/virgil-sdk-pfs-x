//
//  KeyStorage.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

/// Protocol for KeyStorage for PFS
@objc(VSPKeyStorage) public protocol KeyStorage {
    /// Stores key entry
    ///
    /// - Parameter keyEntry: Key entry
    /// - Throws: NSError instances with corresponding description
    func storeKeyEntry(_ keyEntry: KeyEntry) throws
    
    /// Stores muplitple key entries
    ///
    /// - Parameter keyEntries: key entries to store
    /// - Throws: NSError instances with corresponding description
    func storeKeyEntries(_ keyEntries: [KeyEntry]) throws
    
    /// Loads key entry
    ///
    /// - Parameter name: key entry name
    /// - Returns: loaded key entry
    /// - Throws: NSError instances with corresponding description
    func loadKeyEntry(withName name: String) throws -> KeyEntry
    
    /// Deletes key entry
    ///
    /// - Parameter name: key entry name
    /// - Throws: NSError instances with corresponding description
    func deleteKeyEntry(withName name: String) throws
    
    /// Deletes multiple key entries
    ///
    /// - Parameter names: key entries names
    /// - Throws: NSError instances with corresponding description
    func deleteKeyEntries(withNames names: [String]) throws
    
    /// Returns all keys attributes
    ///
    /// - Returns: all keys attributes
    /// - Throws: NSError instances with corresponding description
    func getAllKeysAttrs() throws -> [KeyAttrs]
}
