//
//  InitiationMessage.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/20/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

struct InitiationMessage {
    let initiatorIcId: String
    let responderIcId: String
    let responderLtcId: String
    let responderOtcId: String?
    let ephPublicKey: Data
    let ephPublicKeySignature: Data
    let salt: Data
    let cipherText: Data
}

extension InitiationMessage {
    fileprivate enum Keys: String {
        case initiatorIcId = "initiator_ic_id"
        case responderIcId = "responder_ic_id"
        case responderLtcId = "responder_ltc_id"
        case responderOtcId = "responder_otc_id"
        case eph = "eph"
        case sign = "sign"
        case salt = "salt"
        case cipherText = "ciphertext"
    }
}

extension InitiationMessage: Serializable {
    func serialize() -> NSObject {
        let dict: NSMutableDictionary = [
            Keys.initiatorIcId.rawValue: self.initiatorIcId,
            Keys.responderIcId.rawValue: self.responderIcId,
            Keys.responderLtcId.rawValue: self.responderLtcId,
            Keys.eph.rawValue: self.ephPublicKey.base64EncodedString(),
            Keys.sign.rawValue: self.ephPublicKeySignature.base64EncodedString(),
            Keys.salt.rawValue: self.salt.base64EncodedString(),
            Keys.cipherText.rawValue: self.cipherText.base64EncodedString()
        ]
        
        if let otcId = self.responderOtcId {
            dict[Keys.responderOtcId.rawValue] = otcId
        }
        
        return dict
    }
}

extension InitiationMessage: Deserializable {
    init?(dictionary: Any) {
        guard let dict = dictionary as? [AnyHashable: Any] else {
            return nil
        }
        
        guard let initiatorIcId = dict[Keys.initiatorIcId.rawValue] as? String,
            let responderIcId = dict[Keys.responderIcId.rawValue] as? String,
            let responderLtcId = dict[Keys.responderLtcId.rawValue] as? String,
            let ephPublicKeyStr = dict[Keys.eph.rawValue] as? String,
            let ephPublicKey = Data(base64Encoded: ephPublicKeyStr),
            let ephPublicKeySignatureStr = dict[Keys.sign.rawValue] as? String,
            let ephPublicKeySignature = Data(base64Encoded: ephPublicKeySignatureStr),
            let saltStr = dict[Keys.salt.rawValue] as? String,
            let salt = Data(base64Encoded: saltStr),
            let cipherTextStr = dict[Keys.cipherText.rawValue] as? String,
            let cipherText = Data(base64Encoded: cipherTextStr) else {
                return nil
        }
        
        let responderOtcId = dict[Keys.responderOtcId.rawValue] as? String
        
        self.init(initiatorIcId: initiatorIcId, responderIcId: responderIcId, responderLtcId: responderLtcId, responderOtcId: responderOtcId, ephPublicKey: ephPublicKey, ephPublicKeySignature: ephPublicKeySignature, salt: salt, cipherText: cipherText)
    }
}
