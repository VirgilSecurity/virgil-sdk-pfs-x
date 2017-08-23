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
    static public let ErrorDomain = "VSPSecureChatKeyHelperErrorDomain"
    
    fileprivate let crypto: VSSCryptoProtocol
    fileprivate let keyStorage: KeyStorage
    fileprivate let longTermKeyTtl: TimeInterval
    fileprivate let namesHelper: KeyNamesHelper
    private let mutex = Mutex()
    
    init(crypto: VSSCryptoProtocol, keyStorage: KeyStorage, identityCardId: String, longTermKeyTtl: TimeInterval) {
        self.crypto = crypto
        self.keyStorage = keyStorage
        self.longTermKeyTtl = longTermKeyTtl
        self.namesHelper = KeyNamesHelper(identityCardId: identityCardId)
    }
    
    func persistKeys(keys: [HelperKeyEntry], ltKey: HelperKeyEntry?) throws {
        for key in keys {
            try self.saveOtPrivateKey(key.privateKey, name: key.keyName)
        }
        
        if let ltKey = ltKey {
            try self.saveLtPrivateKey(ltKey.privateKey, name: ltKey.keyName)
        }
    }
    
    func getAllOtCardsIds() throws -> [String] {
        let keysAttrs = try self.keyStorage.getAllKeysAttrs()
        
        return keysAttrs
            .filter({ self.namesHelper.isOtKeyEntryName($0.name) })
            .map({ self.namesHelper.extractCardId(fromOtKeyEntryName: $0.name) })
    }
    
    func hasRelevantLtKey() -> Bool {
        guard let keysAttrs = try? self.keyStorage.getAllKeysAttrs() else {
            return false
        }
        
        let date = Date()
        return keysAttrs.contains(where: { self.namesHelper.isLtKeyEntryName($0.name) && date < $0.creationDate.addingTimeInterval(self.longTermKeyTtl)})
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
extension SecureChatKeyHelper {
    // Session keys
    func getSessionKeys(forSessionWithId sessionId: Data) throws -> SessionKeys {
        let sessionIdStr = sessionId.base64EncodedString()
        let keyEntryName = self.namesHelper.getSessionKeysKeyEntryName(sessionIdStr)
        
        let keyEntry = try self.getKeyEntry(withKeyEntryName: keyEntryName)
        
        return SessionKeys(withData: keyEntry.value)
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
    
    // Lt keys
    func getLtPrivateKey(withName name: String) throws -> VSSPrivateKey {
        let keyEntryName = self.namesHelper.getLtPrivateKeyEntryName(name)
        return try self.getPrivateKey(withKeyEntryName: keyEntryName)
    }
    
    func saveLtPrivateKey(_ key: VSSPrivateKey, name: String) throws {
        let keyEntryName = self.namesHelper.getLtPrivateKeyEntryName(name)
        try self.savePrivateKey(key, keyEntryName: keyEntryName)
    }
    
    // Ot keys
    func getOtPrivateKey(name: String) throws -> VSSPrivateKey {
        let keyEntryName = self.namesHelper.getOtPrivateKeyEntryName(name)
        return try self.getPrivateKey(withKeyEntryName: keyEntryName)
    }
    
    func saveOtPrivateKey(_ key: VSSPrivateKey, name: String) throws {
        let keyEntryName = self.namesHelper.getOtPrivateKeyEntryName(name)
        try self.savePrivateKey(key, keyEntryName: keyEntryName)
    }
    
    func removeOtPrivateKey(withName name: String) throws {
        let keyEntryName = self.namesHelper.getOtPrivateKeyEntryName(name)
        try self.removeKeyEntry(withKeyEntryName: keyEntryName)
    }
}

fileprivate extension SecureChatKeyHelper {
    func savePrivateKey(_ key: VSSPrivateKey, keyEntryName: String) throws {
        let privateKeyData = self.crypto.export(key, withPassword: nil)

        let keyEntry = KeyEntry(name: keyEntryName, value: privateKeyData)

        try self.saveKeyEntry(keyEntry)
    }

    func saveKeyEntry(_ keyEntry: KeyEntry) throws {
        try self.keyStorage.storeKeyEntry(keyEntry)
    }
}

fileprivate extension SecureChatKeyHelper {
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

fileprivate extension SecureChatKeyHelper {
    func removeKeyEntry(withKeyEntryName keyEntryName: String) throws {
        try self.keyStorage.deleteKeyEntry(withName: keyEntryName)
    }
}

fileprivate extension SecureChatKeyHelper {
    class KeyNamesHelper {
        private let identityCardId: String
        
        init(identityCardId: String) {
            self.identityCardId = identityCardId
        }
        
        func extractCardId(fromOtKeyEntryName OtkeyEntryName: String) -> String {
            let prefix = "\(self.getPrivateKeyEntryHeader()).\(KeyNamesHelper.OtPrefix)."
            return OtkeyEntryName.replacingOccurrences(of: prefix, with: "")
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

extension SecureChatKeyHelper {
    struct HelperKeyEntry {
        let privateKey: VSSPrivateKey
        let keyName: String
    }
}

extension SecureChatKeyHelper {
    struct SessionKeys {
        let encryptionKey: Data
        let decryptionKey: Data
    }
}

extension SecureChatKeyHelper.SessionKeys {
    func convertToData() -> Data {
        return self.encryptionKey + self.decryptionKey
    }
    
    init(withData data: Data) {
        self.init(encryptionKey: Data(data.prefix(upTo: data.count / 2)), decryptionKey: Data(data.suffix(from: data.count / 2)))
    }
}
