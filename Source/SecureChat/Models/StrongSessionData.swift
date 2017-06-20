//
//  StrongSessionData.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/20/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

struct StrongSessionData {
    let receiverOtcId: String
    let salt: Data
    let cipherText: Data
}

extension StrongSessionData: Serializable {
    func serialize() -> NSObject {
        let dict: NSDictionary = [
            "receiver_otc_id": self.receiverOtcId,
            "salt": self.salt.base64EncodedString(),
            "ciphertext": self.cipherText.base64EncodedString()
        ]
        
        return dict
    }
}

extension StrongSessionData: Deserializable {
    init?(dictionary: Any) {
        guard let dict = dictionary as? [AnyHashable: Any] else {
            return nil
        }
        
        guard let receiverOtcId = dict["receiver_otc_id"] as? String,
            let saltStr = dict["salt"] as? String,
            let salt = Data(base64Encoded: saltStr),
            let cipherTextStr = dict["ciphertext"] as? String,
            let cipherText = Data(base64Encoded: cipherTextStr) else {
                return nil
        }
        
        self.init(receiverOtcId: receiverOtcId, salt: salt, cipherText: cipherText)
    }
}
