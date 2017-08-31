//
//  ExhaustInfoManager.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

class ExhaustInfoManager {
    fileprivate let cardId: String
    fileprivate let storage: InsensitiveDataStorage
    
    init(cardId: String, storage: InsensitiveDataStorage) {
        self.cardId = cardId
        self.storage = storage
    }
}

extension ExhaustInfoManager {
    func getKeysExhaustInfo() throws -> ExhaustInfo {
        Log.debug("Getting exhaust info")
        
        guard let entry = self.storage.loadValue(forKey: self.getExhaustEntryKey()) as? [String : Any] else {
            return ExhaustInfo(otc: [], ltc: [], sessions: [])
        }
        
        guard let info = ExhaustInfo(dict: entry) else {
            throw SecureChat.makeError(withCode: .corruptedExhaustInfo, description: "Corrupted exhaust info.")
        }
        
        return info
    }
}

extension ExhaustInfoManager {
    func saveKeysExhaustInfo(_ keysExhaustInfo: ExhaustInfo) throws {
        Log.debug("Saving exhaust info")
        
        try self.storage.storeValue(keysExhaustInfo.encode(), forKey: self.getExhaustEntryKey())
    }
}

extension ExhaustInfoManager {
    fileprivate func getExhaustEntryKey() -> String {
        return "VIRGIL.EXHAUSTINFO.OWNER=\(self.cardId)"
    }
}
