//
//  SessionState.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

struct SessionState {
    let creationDate: Date
    let ephKeyName: String
    let recipientPublicKey: VSSPublicKey
    let recipientLongTermPublicKey: VSSPublicKey
    let recipientOneTimeKey: VSSPublicKey?
}

extension SessionState {
    fileprivate enum Keys: String {
        case creationDate = "creationDate"
        case ephKeyName = "eph_key_name"
        case recipientPublicKey = "recipientPublicKey"
        case recipientLongTermPublicKey = "recipientLongTermPublicKey"
        case recipientOneTimeKey = "recipientOneTimeKey"
    }
}

extension SessionState {
    func serialize(crypto: VSSCryptoProtocol) -> NSObject {
        let dict: NSMutableDictionary = [
            Keys.creationDate.rawValue: self.creationDate,
            Keys.ephKeyName.rawValue: self.ephKeyName,
            Keys.recipientPublicKey.rawValue: crypto.export(self.recipientPublicKey),
            Keys.recipientLongTermPublicKey.rawValue: crypto.export(self.recipientLongTermPublicKey),
        ]
        
        if let otKey = self.recipientOneTimeKey {
            dict[Keys.recipientOneTimeKey.rawValue] = crypto.export(otKey)
        }
        
        return dict
    }
}

extension SessionState {
    init?(dictionary: Any, crypto: VSSCryptoProtocol) {
        guard let dict = dictionary as? [AnyHashable: Any] else {
            return nil
        }
        
        guard let date = dict[Keys.creationDate] as? Date,
            let ephKeyName = dict[Keys.ephKeyName.rawValue] as? String,
            let recPubKeyData = dict[Keys.recipientPublicKey.rawValue] as? Data,
            let recLtKeyData = dict[Keys.recipientLongTermPublicKey.rawValue] as? Data else {
                return nil
        }
        
        guard let recPubKey = crypto.importPublicKey(from: recPubKeyData),
            let recLtKey = crypto.importPublicKey(from: recLtKeyData) else {
                return nil
        }
        
        let recOtKey: VSSPublicKey?
        if let recOtKeyData = dict[Keys.recipientOneTimeKey.rawValue] as? Data {
            guard let recOtK = crypto.importPublicKey(from: recOtKeyData) else {
                return nil
            }
            
            recOtKey = recOtK
        }
        else {
            recOtKey = nil
        }
        
        self.init(creationDate: date, ephKeyName: ephKeyName, recipientPublicKey: recPubKey, recipientLongTermPublicKey: recLtKey, recipientOneTimeKey: recOtKey)
    }
}
