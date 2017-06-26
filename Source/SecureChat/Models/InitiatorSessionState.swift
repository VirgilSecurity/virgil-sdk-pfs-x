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
    let sessionId: Data
    let ephKeyName: String
    let recipientCardId: String
    let recipientPublicKey: Data
    let recipientLongTermCardId: String
    let recipientLongTermPublicKey: Data
    let recipientOneTimeCardId: String
    let recipientOneTimePublicKey: Data
}

extension InitiatorSessionState: Serializable {
    func serialize() -> NSObject {
        let dict: NSDictionary = [
            Keys.creationDate.rawValue: self.creationDate,
            Keys.sessionId.rawValue: self.sessionId,
            Keys.ephKeyName.rawValue: self.ephKeyName,
            Keys.recipientCardId.rawValue: self.recipientCardId,
            Keys.recipientPublicKey.rawValue: self.recipientPublicKey,
            Keys.recipientLongTermCardId.rawValue: self.recipientLongTermCardId,
            Keys.recipientLongTermPublicKey.rawValue: self.recipientLongTermPublicKey,
            Keys.recipientOneTimeCardId.rawValue: self.recipientOneTimeCardId,
            Keys.recipientOneTimePublicKey.rawValue: self.recipientOneTimePublicKey
        ]
        
        return dict
    }
}

extension InitiatorSessionState: Deserializable {
    init?(dictionary: Any) {
        guard let dict = dictionary as? [AnyHashable: Any] else {
            return nil
        }
        
        guard let date = dict[Keys.creationDate.rawValue] as? Date,
            let sessionId = dict[Keys.sessionId.rawValue] as? Data,
            let ephKeyName = dict[Keys.ephKeyName.rawValue] as? String,
            let recCardId = dict[Keys.recipientCardId.rawValue] as? String,
            let recPubKeyData = dict[Keys.recipientPublicKey.rawValue] as? Data,
            let recLtCardId = dict[Keys.recipientLongTermCardId.rawValue] as? String,
            let recLtKeyData = dict[Keys.recipientLongTermPublicKey.rawValue] as? Data,
            let recOtCardId = dict[Keys.recipientOneTimeCardId.rawValue] as? String,
            let recOtKeyData = dict[Keys.recipientOneTimePublicKey.rawValue] as? Data else {
                return nil
        }
        
        self.init(creationDate: date, sessionId: sessionId, ephKeyName: ephKeyName, recipientCardId: recCardId, recipientPublicKey: recPubKeyData, recipientLongTermCardId: recLtCardId, recipientLongTermPublicKey: recLtKeyData, recipientOneTimeCardId: recOtCardId, recipientOneTimePublicKey: recOtKeyData)
    }
}

extension InitiatorSessionState {
    fileprivate enum Keys: String {
        case creationDate = "creationDate"
        case sessionId = "session_id"
        case ephKeyName = "eph_key_name"
        case recipientCardId = "recipient_card_id"
        case recipientPublicKey = "recipient_public_key"
        case recipientLongTermCardId = "recipient_long_term_card_id"
        case recipientLongTermPublicKey = "recipient_long_term_public_key"
        case recipientOneTimeCardId = "recipient_one_time_card_id"
        case recipientOneTimePublicKey = "recipient_one_time_public_key"
    }
}
