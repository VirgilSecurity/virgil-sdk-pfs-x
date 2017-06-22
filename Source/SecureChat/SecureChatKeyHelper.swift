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
    
    init(crypto: VSSCryptoProtocol, keyStorage: VSSKeyStorageProtocol) {
        self.crypto = crypto
        self.keyStorage = keyStorage
    }
    
    func saveKeys(keys: [KeyEntry], ltKey: KeyEntry?) throws {
        let serviceInfo = try self.getServiceInfoEntry()
        
        var keyEntryNames: [String] = []
        keyEntryNames.reserveCapacity(keys.count)
        
        for i in 0..<keys.count {
            keyEntryNames.append(try self.saveOtPrivateKey(keys[i].privateKey, keyName: keys[i].keyName))
        }
        
        let ltcKeyEntryName: String?
        if let ltKey = ltKey {
            ltcKeyEntryName = try self.saveLtPrivateKey(ltKey.privateKey, keyName: ltKey.keyName)
        }
        else {
            ltcKeyEntryName = nil
        }
        
        let newServiceInfo = ServiceInfoEntry(ltcKeyName: ltcKeyEntryName ?? serviceInfo.ltcKeyName, otcKeysNames: serviceInfo.otcKeysNames + keyEntryNames)
        
        try self.updateServiceInfoEntry(newEntry: newServiceInfo)
    }
    
    static private let ServiceKeyName = "VIRGIL.SERVICE.INFO"
    private func updateServiceInfoEntry(newEntry: ServiceInfoEntry) throws {
        // FIXME: Replace with update
        try self.keyStorage.deleteKeyEntry(withName: SecureChatKeyHelper.ServiceKeyName)
        
        let data = NSKeyedArchiver.archivedData(withRootObject: newEntry)
        let keyEntry = VSSKeyEntry(name: SecureChatKeyHelper.ServiceKeyName, value: data)
        
        try self.keyStorage.store(keyEntry)
    }
    
    private func getServiceInfoEntry() throws -> ServiceInfoEntry {
        guard let keyEntry = try? self.keyStorage.loadKeyEntry(withName: SecureChatKeyHelper.ServiceKeyName) else {
            throw NSError(domain: SecureChatKeyHelper.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error getting service info key."])
        }
        
        guard let serviceInfoEntry = NSKeyedUnarchiver.unarchiveObject(with: keyEntry.value) as? ServiceInfoEntry else {
            throw NSError(domain: SecureChatKeyHelper.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error unarchiving service info key."])
        }
        
        return serviceInfoEntry
    }
}

// MARK: Keys base functions
extension SecureChatKeyHelper {
    func getEphPrivateKey(keyName: String) throws -> VSSPrivateKey {
        let name = self.getEphPrivateKeyName(keyName)
        return try self.getPrivateKey(keyName: name)
    }
    
    func saveEphPrivateKey(_ key: VSSPrivateKey, keyName: String) throws -> String {
        let name = self.getEphPrivateKeyName(keyName)
        return try self.savePrivateKey(key, keyName: name)
    }
    
    func getLtPrivateKey(keyName: String) throws -> VSSPrivateKey {
        let name = self.getLtPrivateKeyName(keyName)
        return try self.getPrivateKey(keyName: name)
    }
    
    fileprivate func saveLtPrivateKey(_ key: VSSPrivateKey, keyName: String) throws -> String {
        let name = self.getLtPrivateKeyName(keyName)
        return try self.savePrivateKey(key, keyName: name)
    }
    
    func getOtPrivateKey(keyName: String) throws -> VSSPrivateKey {
        let name = self.getOtPrivateKeyName(keyName)
        return try self.getPrivateKey(keyName: name)
    }
    
    fileprivate func saveOtPrivateKey(_ key: VSSPrivateKey, keyName: String) throws -> String {
        let name = self.getOtPrivateKeyName(keyName)
        return try self.savePrivateKey(key, keyName: name)
    }
    
    private func getPrivateKey(keyName: String) throws -> VSSPrivateKey {
        let keyEntryName = self.getPrivateKeyName(keyName)
        
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
