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
    
    init(cardId: String) {
        self.cardId = cardId
    }
}

extension SecureChatExhaustHelper {
    struct OtcExhaustInfo {
        let cardId: String
        let exhaustDate: Date
    }
}

extension SecureChatExhaustHelper.OtcExhaustInfo {
    private enum Keys: String {
        case cardId = "card_id"
        case exhaustDate = "exhaust_date"
    }
    
    fileprivate func encode() -> [String : Any] {
        let dict: [String : Any] = [
            Keys.cardId.rawValue: self.cardId,
            Keys.exhaustDate.rawValue: self.exhaustDate.timeIntervalSince1970
        ]
        
        return dict
    }
    
    fileprivate init?(dict: [String : Any]) {
        guard let cardId = dict[Keys.cardId.rawValue] as? String,
            let exhaustDateInterval = dict[Keys.exhaustDate.rawValue] as? TimeInterval else {
                return nil
        }
        
        self.init(cardId: cardId, exhaustDate: Date(timeIntervalSince1970: exhaustDateInterval))
    }
}

extension SecureChatExhaustHelper {
    func getKeysExhaustInfo() throws -> [OtcExhaustInfo] {
        guard let userDefaults = UserDefaults(suiteName: self.getSuiteName()) else {
            throw SecureChat.makeError(withCode: .creatingUserDefaults, description: "Error while creating UserDefaults.")
        }
        
        return try self.getKeysExhaustInfo(userDefaults: userDefaults)
    }
    
    private func getKeysExhaustInfo(userDefaults: UserDefaults) throws -> [OtcExhaustInfo] {
        guard let entries = userDefaults.value(forKey: self.getExhaustEntryKey()) as? [[String : Any]] else {
            return []
        }
        
        var exhaustInfos = Array<OtcExhaustInfo>()
        for entry in entries {
            guard let exhaustInfo = OtcExhaustInfo(dict: entry) else {
                throw SecureChat.makeError(withCode: .corruptedExhaustInfo, description: "Corrupted exhaust info.")
            }
            
            exhaustInfos.append(exhaustInfo)
        }
        
        return exhaustInfos
    }
}

extension SecureChatExhaustHelper {
    func saveKeysExhaustInfo(_ keysExhaustInfo: [OtcExhaustInfo]) throws {
        guard let userDefaults = UserDefaults(suiteName: self.getSuiteName()) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.creatingUserDefaults.rawValue, userInfo: [NSLocalizedDescriptionKey: "Error while creating UserDefaults."])
        }
        
        self.saveKeysExhaustInfo(keysExhaustInfo, userDefaults: userDefaults)
    }
    
    private func saveKeysExhaustInfo(_ keysExhaustInfo: [OtcExhaustInfo], userDefaults: UserDefaults) {
        userDefaults.set(keysExhaustInfo.map({ $0.encode() }), forKey: self.getExhaustEntryKey())
    }
}

extension SecureChatExhaustHelper {
    static private let DefaultsSuiteName = "VIRGIL.EXHAUST.%@"
    static private let ExhaustEntryKey = "VIRGIL.EXHAUSTINFO"
    
    fileprivate func getExhaustEntryKey() -> String {
        return SecureChatExhaustHelper.ExhaustEntryKey
    }
    
    fileprivate func getSuiteName() -> String {
        return String(format: SecureChatExhaustHelper.DefaultsSuiteName, self.cardId)
    }
}
