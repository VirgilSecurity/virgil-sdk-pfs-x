//
//  SecureChatExhaustHelper.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

class SecureChatExhaustHelper {
    fileprivate let cardId: String
    fileprivate let storage: InsensitiveDataStorage
    
    init(cardId: String, storage: InsensitiveDataStorage) {
        self.cardId = cardId
        self.storage = storage
    }
}

extension SecureChatExhaustHelper {
    func getKeysExhaustInfo() throws -> [OtcExhaustInfo] {
        guard let entries = self.storage.loadValue(forKey: self.getExhaustEntryKey()) as? [[String : Any]] else {
            return []
        }
        
        let exhaustInfos = Array<OtcExhaustInfo>(try entries.map({
            guard let info = OtcExhaustInfo(dict: $0) else {
                throw SecureChat.makeError(withCode: .corruptedExhaustInfo, description: "Corrupted exhaust info.")
            }
            
            return info
        }))
        
        return exhaustInfos
    }
}

extension SecureChatExhaustHelper {
    func saveKeysExhaustInfo(_ keysExhaustInfo: [OtcExhaustInfo]) throws {
        try self.storage.storeValue(keysExhaustInfo.map({ $0.encode() }), forKey: self.getExhaustEntryKey())
    }
}

extension SecureChatExhaustHelper {
    static private let ExhaustEntryKey = "VIRGIL.EXHAUSTINFO"
    
    fileprivate func getExhaustEntryKey() -> String {
        return SecureChatExhaustHelper.ExhaustEntryKey
    }
}
