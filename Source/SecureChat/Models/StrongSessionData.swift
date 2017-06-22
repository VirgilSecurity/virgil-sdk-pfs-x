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

extension StrongSessionData {
    fileprivate enum Keys: String {
        case salt = "salt"
        case ciphertext = "ciphertext"
        case receiverOtcId = "receiver_otc_id"
    }
}

extension StrongSessionData: Serializable {
    func serialize() -> NSObject {
        let dict: NSDictionary = [
            Keys.receiverOtcId.rawValue: self.receiverOtcId,
            Keys.salt.rawValue: self.salt.base64EncodedString(),
            Keys.ciphertext.rawValue: self.cipherText.base64EncodedString()
        ]
        
        return dict
    }
}

extension StrongSessionData: Deserializable {
    init?(dictionary: Any) {
        guard let dict = dictionary as? [AnyHashable: Any] else {
            return nil
        }
        
        guard let receiverOtcId = dict[Keys.receiverOtcId.rawValue] as? String,
            let saltStr = dict[Keys.salt.rawValue] as? String,
            let salt = Data(base64Encoded: saltStr),
            let cipherTextStr = dict[Keys.ciphertext.rawValue] as? String,
            let cipherText = Data(base64Encoded: cipherTextStr) else {
                return nil
        }
        
        self.init(receiverOtcId: receiverOtcId, salt: salt, cipherText: cipherText)
    }
}
