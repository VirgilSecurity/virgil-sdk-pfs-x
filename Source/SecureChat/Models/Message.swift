//
//  Message.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

struct Message {
    let sessionId: Data
    let salt: Data
    let cipherText: Data
}

extension Message {
    fileprivate enum Keys: String {
        case sessionId = "session_id"
        case salt = "salt"
        case ciphertext = "ciphertext"
    }
}

extension Message: Serializable {
    func serialize() -> NSObject {
        let dict: NSDictionary = [
            Keys.sessionId.rawValue: self.sessionId.base64EncodedString(),
            Keys.salt.rawValue: self.salt.base64EncodedString(),
            Keys.ciphertext.rawValue: self.cipherText.base64EncodedString()
        ]
        
        return dict
    }
}

extension Message: Deserializable {
    init?(dictionary: Any) {
        guard let dict = dictionary as? [AnyHashable: Any] else {
            return nil
        }
        
        guard let sessionIdStr = dict[Keys.sessionId.rawValue] as? String,
            let sessionId = Data(base64Encoded: sessionIdStr),
            let saltStr = dict[Keys.salt.rawValue] as? String,
            let salt = Data(base64Encoded: saltStr),
            let cipherTextStr = dict[Keys.ciphertext.rawValue] as? String,
            let cipherText = Data(base64Encoded: cipherTextStr) else {
                return nil
        }
        
        self.init(sessionId: sessionId, salt: salt, cipherText: cipherText)
    }
}
