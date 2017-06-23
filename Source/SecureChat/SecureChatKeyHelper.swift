//
//  SecureChatKeyHelper.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

class SecureChatKeyHelper {
    struct KeyEntry {
        let privateKey: VSSPrivateKey
        let keyName: String
    }
    
    static public let ErrorDomain = "VSPSecureChatKeyHelperErrorDomain"
    
    fileprivate let crypto: VSSCryptoProtocol
    fileprivate let keyStorage: VSSKeyStorageProtocol
    fileprivate let identityCardId: String
    
    init(crypto: VSSCryptoProtocol, keyStorage: VSSKeyStorageProtocol, identityCardId: String) {
        self.crypto = crypto
        self.keyStorage = keyStorage
        self.identityCardId = identityCardId
    }
    
    func saveKeys(keys: [KeyEntry], ltKey: KeyEntry?) throws {
        var keyEntryNames: [String] = []
        keyEntryNames.reserveCapacity(keys.count)
        
        for i in 0..<keys.count {
            keyEntryNames.append(try self.saveOtPrivateKey(keys[i].privateKey, name: keys[i].keyName))
        }
        
        let ltcKeyEntryName: String?
        if let ltKey = ltKey {
            ltcKeyEntryName = try self.saveLtPrivateKey(ltKey.privateKey, name: ltKey.keyName)
        }
        else {
            ltcKeyEntryName = nil
        }
        
        let newServiceInfo: ServiceInfoEntry
        if let serviceInfo = self.getServiceInfoEntry() {
            newServiceInfo = ServiceInfoEntry(ltcKeyName: ltcKeyEntryName ?? serviceInfo.ltcKeyName, otcKeysNames: serviceInfo.otcKeysNames + keyEntryNames)
        }
        else {
            guard let ltcKeyEntryName = ltcKeyEntryName else {
                throw NSError(domain: SecureChatKeyHelper.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "LT key not found and ney key was not specified."])
            }
            newServiceInfo = ServiceInfoEntry(ltcKeyName: ltcKeyEntryName, otcKeysNames: keyEntryNames)
        }
        
        try self.updateServiceInfoEntry(newEntry: newServiceInfo)
    }
    
    static private let ServiceKeyName = "VIRGIL.SERVICE.INFO.%@"
    private func updateServiceInfoEntry(newEntry: ServiceInfoEntry) throws {
        // FIXME: Replace with update
        let entryName = String(format: SecureChatKeyHelper.ServiceKeyName, self.identityCardId)
        
        try? self.keyStorage.deleteKeyEntry(withName: entryName)
        
        let data = NSKeyedArchiver.archivedData(withRootObject: newEntry)
        let keyEntry = VSSKeyEntry(name: entryName, value: data)
        
        try self.keyStorage.store(keyEntry)
    }
    
    private func getServiceInfoEntry() -> ServiceInfoEntry? {
        guard let keyEntry = try? self.keyStorage.loadKeyEntry(withName: SecureChatKeyHelper.ServiceKeyName) else {
            return nil
        }
        
        guard let serviceInfoEntry = NSKeyedUnarchiver.unarchiveObject(with: keyEntry.value) as? ServiceInfoEntry else {
            return nil
        }
        
        return serviceInfoEntry
    }
}

// MARK: Keys base functions
extension SecureChatKeyHelper {
    func getEphPrivateKey(withName name: String) throws -> VSSPrivateKey {
        let keyName = self.getEphPrivateKeyName(name)
        return try self.getPrivateKey(withKeyName: keyName)
    }
    
    func getEphPrivateKey(withKeyEntryName keyEntryName: String) throws -> VSSPrivateKey {
        return try self.getPrivateKey(withKeyEntryName: keyEntryName)
    }
    
    func saveEphPrivateKey(_ key: VSSPrivateKey, name: String) throws -> String {
        let keyName = self.getEphPrivateKeyName(name)
        return try self.savePrivateKey(key, keyName: keyName)
    }
    
    func getLtPrivateKey(withName name: String) throws -> VSSPrivateKey {
        let keyName = self.getLtPrivateKeyName(name)
        return try self.getPrivateKey(withKeyName: keyName)
    }
    
    fileprivate func saveLtPrivateKey(_ key: VSSPrivateKey, name: String) throws -> String {
        let keyName = self.getLtPrivateKeyName(name)
        return try self.savePrivateKey(key, keyName: keyName)
    }
    
    func getOtPrivateKey(name: String) throws -> VSSPrivateKey {
        let keyName = self.getOtPrivateKeyName(name)
        return try self.getPrivateKey(withKeyName: keyName)
    }
    
    fileprivate func saveOtPrivateKey(_ key: VSSPrivateKey, name: String) throws -> String {
        let keyName = self.getOtPrivateKeyName(name)
        return try self.savePrivateKey(key, keyName: keyName)
    }
    
    private func getPrivateKey(withKeyName keyName: String) throws -> VSSPrivateKey {
        let keyEntryName = self.getPrivateKeyName(keyName)
        
        return try self.getPrivateKey(withKeyEntryName: keyEntryName)
    }
    
    private func getPrivateKey(withKeyEntryName keyEntryName: String) throws -> VSSPrivateKey {
        let keyEntry = try self.keyStorage.loadKeyEntry(withName: keyEntryName)
        
        guard let privateKey = self.crypto.importPrivateKey(from: keyEntry.value) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error loading private key."])
        }
        
        return privateKey
    }
    
    private func savePrivateKey(_ key: VSSPrivateKey, keyName: String) throws -> String {
        let privateKeyData = self.crypto.export(key, withPassword: nil)
        
        let keyEntryName = self.getPrivateKeyName(keyName)
        let keyEntry = VSSKeyEntry(name: keyEntryName, value: privateKeyData)
        
        try self.keyStorage.store(keyEntry)
        
        return keyEntryName
    }
    
    private func getPrivateKeyName(_ name: String) -> String {
        return String(format: "VIRGIL.%@", name)
    }
    
    private func getEphPrivateKeyName(_ name: String) -> String {
        return String(format: "EPH_KEY.%@", name)
    }
    
    private func getLtPrivateKeyName(_ name: String) -> String {
        return String(format: "LT_KEY.%@", name)
    }
    
    private func getOtPrivateKeyName(_ name: String) -> String {
        return String(format: "OT_KEY.%@", name)
    }
}
