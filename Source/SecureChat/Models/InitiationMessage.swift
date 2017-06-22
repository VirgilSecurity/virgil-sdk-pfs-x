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
    let receiverIcId: String
    let receiverLtcId: String
    let ephPublicKey: Data
    let ephPublicKeySignature: Data
    let weakSessionData: WeakSessionData
    let strongSessionData: StrongSessionData
}

extension InitiationMessage {
    fileprivate enum Keys: String {
        case initiatorIcId = "initiator_ic_id"
        case receiverIcId = "receiver_ic_id"
        case receiverLtcId = "receiver_ltc_id"
        case eph = "eph"
        case sign = "sign"
        case sessionW = "session_w"
        case sessionS = "session_s"
    }
}

extension InitiationMessage: Serializable {
    func serialize() -> NSObject {
        let dict: NSDictionary = [
            Keys.initiatorIcId.rawValue: self.initiatorIcId,
            Keys.receiverIcId.rawValue: self.receiverIcId,
            Keys.receiverLtcId.rawValue: self.receiverLtcId,
            Keys.eph.rawValue: self.ephPublicKey.base64EncodedString(),
            Keys.sign.rawValue: self.ephPublicKeySignature.base64EncodedString(),
            Keys.sessionW.rawValue: self.weakSessionData.serialize(),
            Keys.sessionS.rawValue: self.strongSessionData.serialize()
        ]
        
        return dict
    }
}

extension InitiationMessage: Deserializable {
    init?(dictionary: Any) {
        guard let dict = dictionary as? [AnyHashable: Any] else {
            return nil
        }
        
        guard let initiatorIcId = dict[Keys.initiatorIcId.rawValue] as? String,
            let receiverIcId = dict[Keys.receiverIcId.rawValue] as? String,
            let receiverLtcId = dict[Keys.receiverLtcId.rawValue] as? String,
            let ephPublicKeyStr = dict[Keys.eph.rawValue] as? String,
            let ephPublicKey = Data(base64Encoded: ephPublicKeyStr),
            let ephPublicKeySignatureStr = dict[Keys.sign.rawValue] as? String,
            let ephPublicKeySignature = Data(base64Encoded: ephPublicKeySignatureStr),
            let weakSessionDataDict = dict[Keys.sessionW.rawValue],
            let strongSessionDataDict = dict[Keys.sessionS.rawValue] else {
                return nil
        }
        
        guard let weakSessionData = WeakSessionData(dictionary: weakSessionDataDict),
            let strongSessionData = StrongSessionData(dictionary: strongSessionDataDict) else {
                return nil
        }
        
        self.init(initiatorIcId: initiatorIcId, receiverIcId: receiverIcId, receiverLtcId: receiverLtcId, ephPublicKey: ephPublicKey, ephPublicKeySignature: ephPublicKeySignature, weakSessionData: weakSessionData, strongSessionData: strongSessionData)
    }
}
