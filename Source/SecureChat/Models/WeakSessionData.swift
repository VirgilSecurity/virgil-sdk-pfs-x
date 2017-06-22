//
//  WeakSessionData.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/20/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

struct WeakSessionData {
    let salt: Data
    let cipherText: Data
}

extension WeakSessionData {
    fileprivate enum Keys: String {
        case salt = "salt"
        case ciphertext = "ciphertext"
    }
}

extension WeakSessionData: Serializable {
    func serialize() -> NSObject {
        let dict: NSDictionary = [
            Keys.salt.rawValue: self.salt.base64EncodedString(),
            Keys.ciphertext.rawValue: self.cipherText.base64EncodedString()
        ]
        
        return dict
    }
}

extension WeakSessionData: Deserializable {
    init?(dictionary: Any) {
        guard let dict = dictionary as? [AnyHashable: Any] else {
            return nil
        }
        
        guard let saltStr = dict[Keys.salt.rawValue] as? String,
            let salt = Data(base64Encoded: saltStr),
            let cipherTextStr = dict[Keys.ciphertext.rawValue] as? String,
            let cipherText = Data(base64Encoded: cipherTextStr) else {
                return nil
        }
        
        self.init(salt: salt, cipherText: cipherText)
    }
}
