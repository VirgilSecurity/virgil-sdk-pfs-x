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
    let additionalData: Data?
    let ephPublicKeyData: Data
    let recipientLongTermCardId: String
    let recipientOneTimeCardId: String
}

extension ResponderSessionState: Serializable {
    func serialize() -> NSObject {
        let dict: NSMutableDictionary = [
            Keys.creationDate.rawValue: self.creationDate,
            Keys.sessionId.rawValue: self.sessionId,
            Keys.ephPublicKeyData.rawValue: self.ephPublicKeyData,
            Keys.recipientLongTermCardId.rawValue: self.recipientLongTermCardId,
            Keys.recipientOneTimeCardId.rawValue: self.recipientOneTimeCardId
        ]
        
        if let ad = self.additionalData {
            dict[Keys.additionalData.rawValue] = ad
        }
        
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
        
        let additionalData = dict[Keys.additionalData.rawValue] as? Data
        
        self.init(creationDate: date, sessionId: sessionId, additionalData: additionalData, ephPublicKeyData: ephPublicKeyData, recipientLongTermCardId: recipientLongTermCardId, recipientOneTimeCardId: recipientOneTimeCardId)
    }
}

extension ResponderSessionState {
    fileprivate enum Keys: String {
        case creationDate = "creation_date"
        case sessionId = "session_id"
        case additionalData = "additional_data"
        case ephPublicKeyData = "eph_public_key_data"
        case recipientLongTermCardId = "recipient_long_term_card_id"
        case recipientOneTimeCardId = "recipient_one_time_card_id"
    }
}
