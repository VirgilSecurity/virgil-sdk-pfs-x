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
    fileprivate let longTermKeyTtl: TimeInterval
    
    init(crypto: VSSCryptoProtocol, keyStorage: VSSKeyStorageProtocol, identityCardId: String, longTermKeyTtl: TimeInterval) {
        self.crypto = crypto
        self.keyStorage = keyStorage
        self.identityCardId = identityCardId
        self.longTermKeyTtl = longTermKeyTtl
    }
    
    func persistEphPrivateKey(_ key: VSSPrivateKey, name: String) throws -> String {
        let ephKeyEntryName = try self.saveEphPrivateKey(key, name: name)
        
        let newServiceInfo: ServiceInfoEntry
        if let serviceInfo = self.getServiceInfoEntry() {
            newServiceInfo = ServiceInfoEntry(ltcKeys: serviceInfo.ltcKeys, otcKeysNames: serviceInfo.otcKeysNames, ephKeysNames: serviceInfo.ephKeysNames + [ephKeyEntryName])
        }
        else {
            newServiceInfo = ServiceInfoEntry(ltcKeys: [], otcKeysNames: [], ephKeysNames: [ephKeyEntryName])
        }
        
        try self.updateServiceInfoEntry(newEntry: newServiceInfo)
        
        return ephKeyEntryName
    }
    
    func persistKeys(keys: [KeyEntry], ltKey: KeyEntry?) throws {
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
            let ltcEntryArray = ltcKeyEntryName == nil ? [] : [ServiceInfoEntry.KeyEntry(keyName: ltcKeyEntryName!, date: Date())]
            newServiceInfo = ServiceInfoEntry(ltcKeys: serviceInfo.ltcKeys + ltcEntryArray, otcKeysNames: serviceInfo.otcKeysNames + keyEntryNames, ephKeysNames: serviceInfo.ephKeysNames)
        }
        else {
            guard let ltcKeyEntryName = ltcKeyEntryName else {
                throw NSError(domain: SecureChatKeyHelper.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "LT key not found and new key was not specified."])
            }
            newServiceInfo = ServiceInfoEntry(ltcKeys: [ServiceInfoEntry.KeyEntry(keyName: ltcKeyEntryName, date: Date())], otcKeysNames: keyEntryNames, ephKeysNames: [])
        }
        
        try self.updateServiceInfoEntry(newEntry: newServiceInfo)
    }
    
    func getAllOtCardsIds() throws -> [String] {
        guard let serviceInfo = self.getServiceInfoEntry() else {
            return []
        }
        
        return serviceInfo.otcKeysNames.map({ self.extractCardId(fromOTKeyEntryName: $0) })
    }
    
    func removeOldKeys(relevantEphKeys: Set<String>, relevantLtCards: Set<String>, relevantOtCards: Set<String>) throws {
        guard let serviceInfoEntry = self.getServiceInfoEntry() else {
            if relevantEphKeys.count > 0 || relevantLtCards.count > 0 || relevantOtCards.count > 0 {
                throw NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Trying to remove keys, but no service entry was found."])
            }
            return
        }
        
        let date = Date()
        let outdatedLtKeysNames = Set<String>(serviceInfoEntry.ltcKeys.filter({ date > $0.date.addingTimeInterval(self.longTermKeyTtl)}).map({ $0.keyName }))
        let ltKeysToRemove = outdatedLtKeysNames.subtracting(Set<String>(relevantLtCards.map({ self.getPrivateKeyName(self.getLtPrivateKeyName($0)) })))
        let otKeysToRemove = Set<String>(serviceInfoEntry.otcKeysNames).subtracting(Set<String>(relevantOtCards.map({ self.getPrivateKeyName(self.getOtPrivateKeyName($0)) })))
        let ephKeysToRemove = Set<String>(serviceInfoEntry.ephKeysNames).subtracting(relevantEphKeys)
        
        for key in ltKeysToRemove.union(otKeysToRemove).union(ephKeysToRemove) {
            try self.removePrivateKey(withKeyEntryName: key)
        }
    }
    
    func removeOneTimePrivateKey(withName name: String) throws {
        let keyEntryName = self.getPrivateKeyName(self.getOtPrivateKeyName(name))
        try self.removePrivateKey(withKeyEntryName: keyEntryName)
    }
    
    func hasRelevantLtKey() -> Bool {
        guard let serviceInfoEntry = self.getServiceInfoEntry() else {
            return false
        }
        
        let date = Date()
        return !serviceInfoEntry.ltcKeys.filter({ date < $0.date.addingTimeInterval(self.longTermKeyTtl)}).isEmpty
    }
    
    private func updateServiceInfoEntry(newEntry: ServiceInfoEntry) throws {
        // FIXME: Replace with update
        let entryName = self.getServiceInfoName()
        try? self.keyStorage.deleteKeyEntry(withName: entryName)
        
        let data = NSKeyedArchiver.archivedData(withRootObject: newEntry)
        let keyEntry = VSSKeyEntry(name: entryName, value: data)
        
        try self.keyStorage.store(keyEntry)
    }
    
    private func getServiceInfoEntry() -> ServiceInfoEntry? {
        guard let keyEntry = try? self.keyStorage.loadKeyEntry(withName: self.getServiceInfoName()) else {
            return nil
        }
        
        guard let serviceInfoEntry = NSKeyedUnarchiver.unarchiveObject(with: keyEntry.value) as? ServiceInfoEntry else {
            return nil
        }
        
        return serviceInfoEntry
    }
}

// Service Info
extension SecureChatKeyHelper {
    static private let ServiceKeyName = "VIRGIL.SERVICE.INFO.%@"
    
    fileprivate func getServiceInfoName() -> String {
        return String(format: SecureChatKeyHelper.ServiceKeyName, self.identityCardId)
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
    
    fileprivate func saveEphPrivateKey(_ key: VSSPrivateKey, name: String) throws -> String {
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
    
    func removePrivateKey(withKeyEntryName keyEntryName: String) throws {
        try self.keyStorage.deleteKeyEntry(withName: keyEntryName)
    }
    
    private func savePrivateKey(_ key: VSSPrivateKey, keyName: String) throws -> String {
        let privateKeyData = self.crypto.export(key, withPassword: nil)
        
        let keyEntryName = self.getPrivateKeyName(keyName)
        let keyEntry = VSSKeyEntry(name: keyEntryName, value: privateKeyData)
        
        try self.keyStorage.store(keyEntry)
        
        return keyEntryName
    }
    
    fileprivate func extractCardId(fromOTKeyEntryName OTkeyEntryName: String) -> String {
        return OTkeyEntryName.replacingOccurrences(of: "VIRGIL.OT_KEY.", with: "")
    }
    
    fileprivate func getPrivateKeyName(_ name: String) -> String {
        return String(format: "VIRGIL.OWNER=%@.%@", self.identityCardId, name)
    }
    
    fileprivate func getEphPrivateKeyName(_ name: String) -> String {
        return String(format: "EPH_KEY.%@", name)
    }
    
    fileprivate func getLtPrivateKeyName(_ name: String) -> String {
        return String(format: "LT_KEY.%@", name)
    }
    
    fileprivate func getOtPrivateKeyName(_ name: String) -> String {
        return String(format: "OT_KEY.%@", name)
    }
}
