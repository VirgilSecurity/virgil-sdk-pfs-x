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

extension InitiationMessage: Serializable {
    func serialize() -> NSObject {
        let dict: NSDictionary = [
            "initiator_ic_id": self.initiatorIcId,
            "receiver_ic_id": self.receiverIcId,
            "receiver_ltc_id": self.receiverLtcId,
            "eph": self.ephPublicKey.base64EncodedString(),
            "sign": self.ephPublicKeySignature.base64EncodedString(),
            "session_w": self.weakSessionData.serialize(),
            "session_s": self.strongSessionData.serialize()
        ]
        
        return dict
    }
}

extension InitiationMessage: Deserializable {
    init?(dictionary: Any) {
        guard let dict = dictionary as? [AnyHashable: Any] else {
            return nil
        }
        
        guard let initiatorIcId = dict["initiator_ic_id"] as? String,
            let receiverIcId = dict["receiver_ic_id"] as? String,
            let receiverLtcId = dict["receiver_ltc_id"] as? String,
            let ephPublicKeyStr = dict["eph"] as? String,
            let ephPublicKey = Data(base64Encoded: ephPublicKeyStr),
            let ephPublicKeySignatureStr = dict["sign"] as? String,
            let ephPublicKeySignature = Data(base64Encoded: ephPublicKeySignatureStr),
            let weakSessionDataDict = dict["session_w"],
            let strongSessionDataDict = dict["session_s"] else {
                return nil
        }
        
        guard let weakSessionData = WeakSessionData(dictionary: weakSessionDataDict),
            let strongSessionData = StrongSessionData(dictionary: strongSessionDataDict) else {
                return nil
        }
        
        self.init(initiatorIcId: initiatorIcId, receiverIcId: receiverIcId, receiverLtcId: receiverLtcId, ephPublicKey: ephPublicKey, ephPublicKeySignature: ephPublicKeySignature, weakSessionData: weakSessionData, strongSessionData: strongSessionData)
    }
}
