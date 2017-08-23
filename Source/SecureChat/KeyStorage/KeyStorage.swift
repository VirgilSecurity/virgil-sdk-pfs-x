//
//  KeyStorage.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

@objc(VSPKeyStorage) public protocol KeyStorage {
    func storeKeyEntry(_ keyEntry: KeyEntry) throws
    
    func storeKeyEntries(_ keyEntries: [KeyEntry]) throws
    
    func updateKeyEntry(_ keyEntry: KeyEntry) throws
    
    func loadKeyEntry(withName name: String) throws -> KeyEntry
    
    func existsKeyEntry(withName name: String) -> Bool
    
    func deleteKeyEntry(withName name: String) throws
    
    func deleteKeyEntries(withNames names: [String]) throws
    
    func getAllKeysAttrs() throws -> [KeyAttrs]
}
