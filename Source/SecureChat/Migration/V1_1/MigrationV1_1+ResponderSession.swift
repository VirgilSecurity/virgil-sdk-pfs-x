//
//  MigrationV1_1+Sessions.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/31/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

extension MigrationV1_1 {
    struct ResponderSessionState {
        let creationDate: Date
        let expirationDate: Date
        let sessionId: Data
        let additionalData: Data?
        let ephPublicKeyData: Data
        let recipientIdentityCardId: String
        let recipientIdentityPublicKey: Data
        let recipientLongTermCardId: String
        let recipientOneTimeCardId: String?
    }
}

extension MigrationV1_1.ResponderSessionState: Serializable {
    func serialize() -> NSObject {
        let dict: NSMutableDictionary = [
            Keys.creationDate.rawValue: self.creationDate,
            Keys.expirationDate.rawValue: self.expirationDate,
            Keys.sessionId.rawValue: self.sessionId,
            Keys.ephPublicKeyData.rawValue: self.ephPublicKeyData,
            Keys.recipientIdentityCardId.rawValue: self.recipientIdentityCardId,
            Keys.recipientIdentityPublicKey.rawValue: self.recipientIdentityPublicKey,
            Keys.recipientLongTermCardId.rawValue: self.recipientLongTermCardId
        ]
        
        if let ad = self.additionalData {
            dict[Keys.additionalData.rawValue] = ad
        }
        
        if let recOtId = self.recipientOneTimeCardId {
            dict[Keys.recipientOneTimeCardId.rawValue] = recOtId
        }
        
        return dict
    }
}

extension MigrationV1_1.ResponderSessionState: Deserializable {
    init?(dictionary: Any) {
        guard let dict = dictionary as? [AnyHashable: Any] else {
            return nil
        }
        
        guard let date = dict[Keys.creationDate.rawValue] as? Date,
            let expirationDate = dict[Keys.expirationDate.rawValue] as? Date,
            let sessionId = dict[Keys.sessionId.rawValue] as? Data,
            let ephPublicKeyData = dict[Keys.ephPublicKeyData.rawValue] as? Data,
            let recipientIdentityCardId = dict[Keys.recipientIdentityCardId.rawValue] as? String,
            let recipientIdentityPublicKey = dict[Keys.recipientIdentityPublicKey.rawValue] as? Data,
            let recipientLongTermCardId = dict[Keys.recipientLongTermCardId.rawValue] as? String else {
                return nil
        }
        
        let additionalData = dict[Keys.additionalData.rawValue] as? Data
        
        let recipientOneTimeCardId = dict[Keys.recipientOneTimeCardId.rawValue] as? String
        
        self.init(creationDate: date, expirationDate: expirationDate, sessionId: sessionId, additionalData: additionalData, ephPublicKeyData: ephPublicKeyData, recipientIdentityCardId: recipientIdentityCardId, recipientIdentityPublicKey: recipientIdentityPublicKey, recipientLongTermCardId: recipientLongTermCardId, recipientOneTimeCardId: recipientOneTimeCardId)
    }
}

extension MigrationV1_1.ResponderSessionState {
    fileprivate enum Keys: String {
        case creationDate = "creation_date"
        case expirationDate = "expiration_date"
        case sessionId = "session_id"
        case additionalData = "additional_data"
        case ephPublicKeyData = "eph_public_key_data"
        case recipientIdentityCardId = "recipient_identity_card_id"
        case recipientIdentityPublicKey = "recipient_identity_public_key"
        case recipientLongTermCardId = "recipient_long_term_card_id"
        case recipientOneTimeCardId = "recipient_one_time_card_id"
    }
}
