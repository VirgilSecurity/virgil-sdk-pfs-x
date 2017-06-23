//
//  InitiatorSessionState.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

struct InitiatorSessionState: SessionState {
    let creationDate: Date
    let ephKeyName: String
    let recipientPublicKey: VSSPublicKey
    let recipientLongTermPublicKey: VSSPublicKey
    let recipientOneTimePublicKey: VSSPublicKey
}

extension InitiatorSessionState {
    func serialize(crypto: VSSCryptoProtocol) -> NSObject {
        let dict: NSDictionary = [
            Keys.creationDate.rawValue: self.creationDate,
            Keys.ephKeyName.rawValue: self.ephKeyName,
            Keys.recipientPublicKey.rawValue: crypto.export(self.recipientPublicKey),
            Keys.recipientLongTermPublicKey.rawValue: crypto.export(self.recipientLongTermPublicKey),
            Keys.recipientOneTimePublicKey.rawValue: crypto.export(self.recipientOneTimePublicKey)
        ]
        
        return dict
    }
}

extension InitiatorSessionState {
    init?(dictionary: Any, crypto: VSSCryptoProtocol) {
        guard let dict = dictionary as? [AnyHashable: Any] else {
            return nil
        }
        
        guard let date = dict[Keys.creationDate] as? Date,
            let ephKeyName = dict[Keys.ephKeyName.rawValue] as? String,
            let recPubKeyData = dict[Keys.recipientPublicKey.rawValue] as? Data,
            let recLtKeyData = dict[Keys.recipientLongTermPublicKey.rawValue] as? Data,
            let recOtKeyData = dict[Keys.recipientOneTimePublicKey.rawValue] as? Data else {
                return nil
        }
        
        guard let recPubKey = crypto.importPublicKey(from: recPubKeyData),
            let recLtKey = crypto.importPublicKey(from: recLtKeyData),
            let recOtKey = crypto.importPublicKey(from: recOtKeyData) else {
                return nil
        }
        
        self.init(creationDate: date, ephKeyName: ephKeyName, recipientPublicKey: recPubKey, recipientLongTermPublicKey: recLtKey, recipientOneTimePublicKey: recOtKey)
    }
}

extension InitiatorSessionState {
    fileprivate enum Keys: String {
        case creationDate = "creationDate"
        case ephKeyName = "eph_key_name"
        case recipientPublicKey = "recipientPublicKey"
        case recipientLongTermPublicKey = "recipientLongTermPublicKey"
        case recipientOneTimePublicKey = "recipientOneTimePublicKey"
    }
}
