//
//  ResponderSessionState.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/23/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

struct ResponderSessionState: SessionState {
    let creationDate: Date
    let sessionId: Data
    let ephPublicKeyData: Data
    let recipientLongTermCardId: String
    let recipientOneTimeCardId: String
}

extension ResponderSessionState: Serializable {
    func serialize() -> NSObject {
        let dict: NSDictionary = [
            Keys.creationDate.rawValue: self.creationDate,
            Keys.sessionId.rawValue: self.sessionId,
            Keys.ephPublicKeyData.rawValue: self.ephPublicKeyData,
            Keys.recipientLongTermCardId.rawValue: self.recipientLongTermCardId,
            Keys.recipientOneTimeCardId.rawValue: self.recipientOneTimeCardId
        ]
        
        return dict
    }
}

extension ResponderSessionState: Deserializable {
    init?(dictionary: Any) {
        guard let dict = dictionary as? [AnyHashable: Any] else {
            return nil
        }
        
        guard let date = dict[Keys.creationDate.rawValue] as? Date,
            let sessionId = dict[Keys.sessionId.rawValue] as? Data,
            let ephPublicKeyData = dict[Keys.ephPublicKeyData.rawValue] as? Data,
            let recipientLongTermCardId = dict[Keys.recipientLongTermCardId.rawValue] as? String,
            let recipientOneTimeCardId = dict[Keys.recipientOneTimeCardId.rawValue] as? String else {
                return nil
        }
        
        self.init(creationDate: date, sessionId: sessionId, ephPublicKeyData: ephPublicKeyData, recipientLongTermCardId: recipientLongTermCardId, recipientOneTimeCardId: recipientOneTimeCardId)
    }
}

extension ResponderSessionState {
    fileprivate enum Keys: String {
        case creationDate = "creationDate"
        case sessionId = "session_id"
        case ephPublicKeyData = "eph_public_key_data"
        case recipientLongTermCardId = "recipient_long_term_card_id"
        case recipientOneTimeCardId = "recipient_one_time_card_id"
    }
}
