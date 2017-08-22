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
    
    struct SessionKeys {
        let encryptionKey: Data
        let decryptionKey: Data
        
        func convertToData() -> Data {
            return self.encryptionKey + self.decryptionKey
        }
        
        init(withData data: Data) {
            self.init(encryptionKey: Data(data.prefix(upTo: data.count / 2)), decryptionKey: Data(data.suffix(from: data.count / 2)))
        }
        
        init(encryptionKey: Data, decryptionKey: Data) {
            self.encryptionKey = encryptionKey
            self.decryptionKey = decryptionKey
        }
    }
    
    static public let ErrorDomain = "VSPSecureChatKeyHelperErrorDomain"
    
    fileprivate let crypto: VSSCryptoProtocol
    fileprivate let keyStorage: VSSKeyStorageProtocol
    fileprivate let identityCardId: String
    fileprivate let longTermKeyTtl: TimeInterval
    private let mutex = Mutex()
    
    init(crypto: VSSCryptoProtocol, keyStorage: VSSKeyStorageProtocol, identityCardId: String, longTermKeyTtl: TimeInterval) {
        self.crypto = crypto
        self.keyStorage = keyStorage
        self.identityCardId = identityCardId
        self.longTermKeyTtl = longTermKeyTtl
    }
    
    func persistKeys(keys: [KeyEntry], ltKey: KeyEntry?) throws {
        self.mutex.lock()
        defer {
            self.mutex.unlock()
        }
        
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
        if let serviceInfo = try self.getServiceInfoEntry() {
            let ltcEntryArray = ltcKeyEntryName == nil ? [] : [ServiceInfoEntry.KeyEntry(keyName: ltcKeyEntryName!, date: Date())]
            newServiceInfo = ServiceInfoEntry(ltcKeys: serviceInfo.ltcKeys + ltcEntryArray, otcKeysNames: serviceInfo.otcKeysNames + keyEntryNames)
        }
        else {
            guard let ltcKeyEntryName = ltcKeyEntryName else {
                throw NSError(domain: SecureChatKeyHelper.ErrorDomain, code: SecureChatErrorCode.longTermKeyNotFoundAndNewKeyNowSpecified.rawValue, userInfo: [NSLocalizedDescriptionKey: "LT key not found and new key was not specified."])
            }
            newServiceInfo = ServiceInfoEntry(ltcKeys: [ServiceInfoEntry.KeyEntry(keyName: ltcKeyEntryName, date: Date())], otcKeysNames: keyEntryNames)
        }
        
        try self.updateServiceInfoEntry(newEntry: newServiceInfo)
    }
    
    func getAllOtCardsIds() throws -> [String] {
        guard let serviceInfo = try self.getServiceInfoEntry() else {
            return []
        }
        
        return serviceInfo.otcKeysNames.map({ self.extractCardId(fromOTKeyEntryName: $0) })
    }
    
    func removeOneTimePrivateKey(withName name: String) throws {
        self.mutex.lock()
        defer {
            self.mutex.unlock()
        }
        
        guard let serviceInfoEntry = try self.getServiceInfoEntry() else {
            throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.tryingToRemoveKeysWithoutServiceEntry.rawValue, userInfo: [NSLocalizedDescriptionKey: "Trying to remove keys, but no service entry was found."])
        }
        
        let keyEntryName = self.getPrivateKeyEntryName(self.getOtPrivateKeyName(name))
        try self.removePrivateKey(withKeyEntryName: keyEntryName)
        
        let newServiceInfo = ServiceInfoEntry(ltcKeys: serviceInfoEntry.ltcKeys, otcKeysNames: serviceInfoEntry.otcKeysNames.filter({ $0 != keyEntryName }))
        
        try self.updateServiceInfoEntry(newEntry: newServiceInfo)
    }
    
    func hasRelevantLtKey() -> Bool {
        guard case let serviceInfoEntry?? = try? self.getServiceInfoEntry() else {
            return false
        }
        
        let date = Date()
        return !serviceInfoEntry.ltcKeys.filter({ date < $0.date.addingTimeInterval(self.longTermKeyTtl)}).isEmpty
    }
    
    private func updateServiceInfoEntry(newEntry: ServiceInfoEntry) throws {
        // FIXME: Replace with update
        let entryName = self.getServiceInfoName()
        try? self.keyStorage.deleteKeyEntry(withName: entryName)
        
        let data: Data
        do {
            data = try newEntry.encode()
        }
        catch {
            throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.encodingServiceInfo.rawValue, userInfo: [NSLocalizedDescriptionKey: "Error while encoding ServiceInfo."])
        }
        let keyEntry = VSSKeyEntry(name: entryName, value: data)
        
        try self.keyStorage.store(keyEntry)
    }
    
    private func getServiceInfoEntry() throws -> ServiceInfoEntry? {
        guard let keyEntry = try? self.keyStorage.loadKeyEntry(withName: self.getServiceInfoName()) else {
            return nil
        }
        
        guard let serviceInfoEntry = ServiceInfoEntry(data: keyEntry.value) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.decodingServiceInfo.rawValue, userInfo: [NSLocalizedDescriptionKey: "Error while decoding ServiceInfo."])
        }
        
        return serviceInfoEntry
    }
    
    func gentleReset() {
        self.mutex.lock()
        defer {
            self.mutex.unlock()
        }
        
        guard case let serviceInfoEntry?? = try? self.getServiceInfoEntry() else {
            return
        }
        
        for keyEntryName in serviceInfoEntry.ltcKeys.map({ $0.keyName }) + serviceInfoEntry.otcKeysNames {
            try? self.removePrivateKey(withKeyEntryName: keyEntryName)
        }
        
        try? self.keyStorage.deleteKeyEntry(withName: self.getServiceInfoName())
    }
}

// Service Info
extension SecureChatKeyHelper {
    static private let ServiceKeyName = "VIRGIL.SERVICE.INFO.%@"
    
    fileprivate func getServiceInfoName() -> String {
        return String(format: SecureChatKeyHelper.ServiceKeyName, self.identityCardId)
    }
}

// MARK: Keys existence
extension SecureChatKeyHelper {
    func otKeyExists(otName: String) -> Bool {
        let keyEntryName = self.getPrivateKeyEntryName(self.getOtPrivateKeyName(otName))
        
        return self.keyEntryExists(keyEntryName: keyEntryName)
    }
    
    func sessionKeysExist(forSessionWithId sessionId: Data) -> Bool {
        let sessionIdStr = sessionId.base64EncodedString()
        let keyEntryName = self.getSessionKeysEntryName(sessionIdStr)
        
        return self.keyEntryExists(keyEntryName: keyEntryName)
    }
}

// MARK: Keys base functions
extension SecureChatKeyHelper {
    func getSessionKeys(forSessionWithId sessionId: Data) throws -> SessionKeys {
        let sessionIdStr = sessionId.base64EncodedString()
        let keyEntry = try self.getKeyEntry(withKeyEntryName: self.getSessionKeysEntryName(sessionIdStr))
        
        return SessionKeys(withData: keyEntry.value)
    }
    
    func saveSessionKeys(_ sessionKeys: SessionKeys, forSessionWithId sessionId: Data) throws {
        let sessionIdStr = sessionId.base64EncodedString()
        let keyEntry = VSSKeyEntry(name: self.getSessionKeysEntryName(sessionIdStr), value: sessionKeys.convertToData())
        
        try self.saveKeyEntry(keyEntry)
    }
    
    func removeSessionKeys(forSessionWithId sessionId: Data) throws {
        let sessionIdStr = sessionId.base64EncodedString()
        let keyEntryName = self.getSessionKeysEntryName(sessionIdStr)
        
        try self.removePrivateKey(withKeyEntryName: keyEntryName)
    }

    fileprivate func getSessionKeysEntryName(_ name: String) -> String {
        return self.getPrivateKeyEntryName(String(format: "SESSION_KEYS.%@", name))
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
        let keyEntryName = self.getPrivateKeyEntryName(keyName)
        
        return try self.getPrivateKey(withKeyEntryName: keyEntryName)
    }
    
    private func getKeyEntry(withKeyEntryName keyEntryName: String) throws -> VSSKeyEntry {
        return try self.keyStorage.loadKeyEntry(withName: keyEntryName)
    }
    
    private func getPrivateKey(withKeyEntryName keyEntryName: String) throws -> VSSPrivateKey {
        let keyEntry = try self.getKeyEntry(withKeyEntryName: keyEntryName)
        
        guard let privateKey = self.crypto.importPrivateKey(from: keyEntry.value) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.loadingPrivateKey.rawValue, userInfo: [NSLocalizedDescriptionKey: "Error loading private key."])
        }
        
        return privateKey
    }
    
    fileprivate func removePrivateKey(withKeyEntryName keyEntryName: String) throws {
        try self.keyStorage.deleteKeyEntry(withName: keyEntryName)
    }
    
    private func savePrivateKey(_ key: VSSPrivateKey, keyName: String) throws -> String {
        let privateKeyData = self.crypto.export(key, withPassword: nil)
        
        let keyEntryName = self.getPrivateKeyEntryName(keyName)
        let keyEntry = VSSKeyEntry(name: keyEntryName, value: privateKeyData)
        
        try self.saveKeyEntry(keyEntry)
        
        return keyEntryName
    }
    
    private func saveKeyEntry(_ keyEntry: VSSKeyEntry) throws {
        try self.keyStorage.store(keyEntry)
    }
    
    fileprivate func extractCardId(fromOTKeyEntryName OTkeyEntryName: String) -> String {
        return OTkeyEntryName.replacingOccurrences(of: self.getPrivateKeyEntryHeader() + self.getOtPrivateKeyNameHeader(), with: "")
    }
    
    private func getPrivateKeyEntryHeader() -> String {
        return String(format: "VIRGIL.OWNER=%@.", self.identityCardId)
    }
    
    fileprivate func getPrivateKeyEntryName(_ name: String) -> String {
        return String(format: "%@%@", self.getPrivateKeyEntryHeader(), name)
    }
    
    fileprivate func getLtPrivateKeyName(_ name: String) -> String {
        return String(format: "LT_KEY.%@", name)
    }
    
    private func getOtPrivateKeyNameHeader() -> String {
        return "OT_KEY."
    }
    
    fileprivate func getOtPrivateKeyName(_ name: String) -> String {
        return String(format: "%@%@", self.getOtPrivateKeyNameHeader(), name)
    }
    
    fileprivate func keyEntryExists(keyEntryName: String) -> Bool {
        return self.keyStorage.existsKeyEntry(withName: keyEntryName)
    }
}
