//
//  KeyStorageManager.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

class KeyStorageManager {
    static public let ErrorDomain = "VSPKeyStorageManagerErrorDomain"
    
    fileprivate let crypto: VSSCryptoProtocol
    fileprivate let keyStorage: KeyStorage
    fileprivate let namesHelper: KeyNamesHelper
    
    init(crypto: VSSCryptoProtocol, keyStorage: KeyStorage, identityCardId: String) {
        self.crypto = crypto
        self.keyStorage = keyStorage
        self.namesHelper = KeyNamesHelper(identityCardId: identityCardId)
    }
    
    func saveKeys(otKeys: [HelperKeyEntry], ltKey: HelperKeyEntry?) throws {
        try self.saveOtPrivateKeys(otKeys.map({ $0.privateKey }), names: otKeys.map({ $0.name }))
        
        if let ltKey = ltKey {
            try self.saveLtPrivateKey(ltKey.privateKey, name: ltKey.name)
        }
    }
    
    func hasRelevantLtKey(now: Date = Date(), longTermKeyTtl: TimeInterval) -> Bool {
        guard let keysAttrs = try? self.keyStorage.getAllKeysAttrs() else {
            return false
        }
        
        return keysAttrs.contains(where: { self.namesHelper.isLtKeyEntryName($0.name) && now < $0.creationDate.addingTimeInterval(longTermKeyTtl)})
    }
    
    func gentleReset() {
        let keysAttrs = (try? self.keyStorage.getAllKeysAttrs()) ?? []
        
        for keyAttrs in keysAttrs {
            if self.namesHelper.isPfsKeyEntryName(keyAttrs.name) {
                try? self.removeKeyEntry(withKeyEntryName: keyAttrs.name)
            }
        }
    }
}

// MARK: Keys base functions
extension KeyStorageManager {
    // Session keys
    func getSessionKeys(forSessionWithId sessionId: Data) throws -> SessionKeys {
        let sessionIdStr = sessionId.base64EncodedString()
        let keyEntryName = self.namesHelper.getSessionKeysKeyEntryName(sessionIdStr)
        
        let keyEntry = try self.getKeyEntry(withKeyEntryName: keyEntryName)
        
        return SessionKeys(withData: keyEntry.value)
    }
    
    func getAllKeysAttrs() throws -> (session: [KeyAttrs], lt: [KeyAttrs], ot: [KeyAttrs]) {
        let keysAttrs = try self.keyStorage.getAllKeysAttrs()
        
        let sessions = keysAttrs
            .filter({ self.namesHelper.isSessionKeysKeyEntryName($0.name) })
            .compactMap({ (attrs: KeyAttrs) -> KeyAttrs? in
                guard let sessionId = self.namesHelper.extractSessionId(fromSessKeyEntryName: attrs.name) else {
                    return nil
                }
                
                return KeyAttrs(name: sessionId.base64EncodedString(), creationDate: attrs.creationDate)
            })
        
        let lt = keysAttrs
            .filter({ self.namesHelper.isLtKeyEntryName($0.name) })
            .map({ (attrs: KeyAttrs) -> KeyAttrs in
                let cardId = self.namesHelper.extractCardId(fromLtKeyEntryName: attrs.name)
                return KeyAttrs(name: cardId, creationDate: attrs.creationDate)
            })
        
        let ot = keysAttrs
            .filter({ self.namesHelper.isOtKeyEntryName($0.name) })
            .map({ (attrs: KeyAttrs) -> KeyAttrs in
                let cardId = self.namesHelper.extractCardId(fromOtKeyEntryName: attrs.name)
                return KeyAttrs(name: cardId, creationDate: attrs.creationDate)
            })
        
        return (session: sessions, lt: lt, ot: ot)
    }
    
    func saveSessionKeys(_ sessionKeys: SessionKeys, forSessionWithId sessionId: Data) throws {
        let sessionIdStr = sessionId.base64EncodedString()
        let keyEntryName = self.namesHelper.getSessionKeysKeyEntryName(sessionIdStr)
        
        let keyEntry = KeyEntry(name: keyEntryName, value: sessionKeys.convertToData())
        
        try self.saveKeyEntry(keyEntry)
    }
    
    func removeSessionKeys(forSessionWithId sessionId: Data) throws {
        let sessionIdStr = sessionId.base64EncodedString()
        let keyEntryName = self.namesHelper.getSessionKeysKeyEntryName(sessionIdStr)
        
        try self.removeKeyEntry(withKeyEntryName: keyEntryName)
    }
    
    func removeSessionKeys(forSessionsWithIds sessionIds: [Data]) throws {
        let keyEntryNames = sessionIds
            .map({ $0.base64EncodedString() })
            .map({ self.namesHelper.getSessionKeysKeyEntryName($0) })
        
        try self.removeKeyEntries(withKeyEntryNames: keyEntryNames)
    }
    
    // Lt keys
    func getLtPrivateKey(withName name: String) throws -> VSSPrivateKey {
        let keyEntryName = self.namesHelper.getLtPrivateKeyEntryName(name)
        return try self.getPrivateKey(withKeyEntryName: keyEntryName)
    }
    
    fileprivate func saveLtPrivateKey(_ key: VSSPrivateKey, name: String) throws {
        let keyEntryName = self.namesHelper.getLtPrivateKeyEntryName(name)
        try self.savePrivateKey(key, keyEntryName: keyEntryName)
    }
    
    func removeLtPrivateKeys(withNames names: [String]) throws {
        let keyEntryNames = names.map({ self.namesHelper.getLtPrivateKeyEntryName($0) })
        try self.removeKeyEntries(withKeyEntryNames: keyEntryNames)
    }
    
    // Ot keys
    func getOtPrivateKey(withName name: String) throws -> VSSPrivateKey {
        let keyEntryName = self.namesHelper.getOtPrivateKeyEntryName(name)
        return try self.getPrivateKey(withKeyEntryName: keyEntryName)
    }
    
    fileprivate func saveOtPrivateKeys(_ keys: [VSSPrivateKey], names: [String]) throws {
        let keyEntryNames = names.map({ self.namesHelper.getOtPrivateKeyEntryName($0) })
        try self.savePrivateKeys(keys, keyEntryNames: keyEntryNames)
    }
    
    func removeOtPrivateKey(withName name: String) throws {
        let keyEntryName = self.namesHelper.getOtPrivateKeyEntryName(name)
        try self.removeKeyEntry(withKeyEntryName: keyEntryName)
    }
    
    func removeOtPrivateKeys(withNames names: [String]) throws {
        let keyEntryNames = names.map({ self.namesHelper.getOtPrivateKeyEntryName($0) })
        try self.removeKeyEntries(withKeyEntryNames: keyEntryNames)
    }
}

fileprivate extension KeyStorageManager {
    func savePrivateKey(_ key: VSSPrivateKey, keyEntryName: String) throws {
        let privateKeyData = self.crypto.export(key, withPassword: nil)

        let keyEntry = KeyEntry(name: keyEntryName, value: privateKeyData)

        try self.saveKeyEntry(keyEntry)
    }
    
    func savePrivateKeys(_ keys: [VSSPrivateKey], keyEntryNames: [String]) throws {
        let keyEntries = zip(keys, keyEntryNames).map({ (key: VSSPrivateKey, keyEntryName: String) -> KeyEntry in
            let privateKeyData = self.crypto.export(key, withPassword: nil)
            return KeyEntry(name: keyEntryName, value: privateKeyData)
        })
        
        try self.saveKeyEntries(keyEntries)
    }

    func saveKeyEntry(_ keyEntry: KeyEntry) throws {
        try self.keyStorage.storeKeyEntry(keyEntry)
    }
    
    func saveKeyEntries(_ keyEntries: [KeyEntry]) throws {
        try self.keyStorage.storeKeyEntries(keyEntries)
    }
}

fileprivate extension KeyStorageManager {
    func getPrivateKey(withKeyEntryName keyEntryName: String) throws -> VSSPrivateKey {
        let keyEntry = try self.getKeyEntry(withKeyEntryName: keyEntryName)
        
        guard let privateKey = self.crypto.importPrivateKey(from: keyEntry.value) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.loadingPrivateKey.rawValue, userInfo: [NSLocalizedDescriptionKey: "Error loading private key."])
        }
        
        return privateKey
    }
    
    func getKeyEntry(withKeyEntryName keyEntryName: String) throws -> KeyEntry {
        return try self.keyStorage.loadKeyEntry(withName: keyEntryName)
    }
}

fileprivate extension KeyStorageManager {
    func removeKeyEntry(withKeyEntryName keyEntryName: String) throws {
        try self.keyStorage.deleteKeyEntry(withName: keyEntryName)
    }
    
    func removeKeyEntries(withKeyEntryNames keyEntryNames: [String]) throws {
        try self.keyStorage.deleteKeyEntries(withNames: keyEntryNames)
    }
}

fileprivate extension KeyStorageManager {
    class KeyNamesHelper {
        private let identityCardId: String
        
        init(identityCardId: String) {
            self.identityCardId = identityCardId
        }
        
        func extractCardId(fromOtKeyEntryName keyEntryName: String) -> String {
            let prefix = "\(self.getPrivateKeyEntryHeader()).\(KeyNamesHelper.OtPrefix)."
            return keyEntryName.replacingOccurrences(of: prefix, with: "")
        }
        
        func extractCardId(fromLtKeyEntryName keyEntryName: String) -> String {
            let prefix = "\(self.getPrivateKeyEntryHeader()).\(KeyNamesHelper.LtPrefix)."
            return keyEntryName.replacingOccurrences(of: prefix, with: "")
        }
        
        func extractSessionId(fromSessKeyEntryName keyEntryName: String) -> Data? {
            let prefix = "\(self.getPrivateKeyEntryHeader()).\(KeyNamesHelper.SessPrefix)."
            let name = keyEntryName.replacingOccurrences(of: prefix, with: "")
            return Data(base64Encoded: name)
        }
        
        func isPfsKeyEntryName(_ keyEntryName: String) -> Bool {
            return self.isOtKeyEntryName(keyEntryName) || self.isLtKeyEntryName(keyEntryName) || self.isSessionKeysKeyEntryName(keyEntryName)
        }
        
        func getSessionKeysKeyEntryName(_ name: String) -> String {
            return "\(self.getPrivateKeyEntryHeader()).\(KeyNamesHelper.SessPrefix).\(name)"
        }
        
        func isSessionKeysKeyEntryName(_ keyEntryName: String) -> Bool {
            return keyEntryName.range(of: "\(self.getPrivateKeyEntryHeader()).\(KeyNamesHelper.SessPrefix).") != .none
        }
        
        func getLtPrivateKeyEntryName(_ name: String) -> String {
            return "\(self.getPrivateKeyEntryHeader()).\(KeyNamesHelper.LtPrefix).\(name)"
        }
        
        func isLtKeyEntryName(_ keyEntryName: String) -> Bool {
            return keyEntryName.range(of: "\(self.getPrivateKeyEntryHeader()).\(KeyNamesHelper.LtPrefix).") != .none
        }
        
        func getOtPrivateKeyEntryName(_ name: String) -> String {
            return "\(self.getPrivateKeyEntryHeader()).\(KeyNamesHelper.OtPrefix).\(name)"
        }
        
        func isOtKeyEntryName(_ keyEntryName: String) -> Bool {
            return keyEntryName.range(of: "\(self.getPrivateKeyEntryHeader()).\(KeyNamesHelper.OtPrefix).") != .none
        }
        
        private func getPrivateKeyEntryName(_ name: String) -> String {
            return String(format: "%@%@", self.getPrivateKeyEntryHeader(), name)
        }
        
        private static let OtPrefix = "OT_KEY"
        private static let LtPrefix = "LT_KEY"
        private static let SessPrefix = "SESS_KEYS"
        
        private func getPrivateKeyEntryHeader() -> String {
            return "VIRGIL.OWNER=\(self.identityCardId)"
        }
    }
}

extension KeyStorageManager {
    struct HelperKeyEntry {
        let privateKey: VSSPrivateKey
        let name: String
    }
}

extension KeyStorageManager {
    struct SessionKeys {
        let encryptionKey: Data
        let decryptionKey: Data
    }
}

extension KeyStorageManager.SessionKeys {
    func convertToData() -> Data {
        return self.encryptionKey + self.decryptionKey
    }
    
    init(withData data: Data) {
        self.init(encryptionKey: Data(data.prefix(upTo: data.count / 2)), decryptionKey: Data(data.suffix(from: data.count / 2)))
    }
}
