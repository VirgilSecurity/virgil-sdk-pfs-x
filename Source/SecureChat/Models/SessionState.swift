//
//  SessionState.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/23/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

struct SessionState {
    let creationDate: Date
    let expirationDate: Date
    let sessionId: Data
    let additionalData: Data
}

extension SessionState {
    func isExpired(now: Date) -> Bool {
        return (now > self.expirationDate)
    }
}

extension SessionState: Serializable {
    func serialize() -> NSObject {
        let dict: NSMutableDictionary = [
            Keys.creationDate.rawValue: self.creationDate,
            Keys.expirationDate.rawValue: self.expirationDate,
            Keys.sessionId.rawValue: self.sessionId,
            Keys.additionalData.rawValue: self.additionalData
        ]
        
        return dict
    }
}

extension SessionState: Deserializable {
    init?(dictionary: Any) {
        guard let dict = dictionary as? [AnyHashable: Any] else {
            return nil
        }
        
        guard let date = dict[Keys.creationDate.rawValue] as? Date,
            let expirationDate = dict[Keys.expirationDate.rawValue] as? Date,
            let sessionId = dict[Keys.sessionId.rawValue] as? Data,
            let additionalData = dict[Keys.additionalData.rawValue] as? Data else {
                return nil
        }

        self.init(creationDate: date, expirationDate: expirationDate, sessionId: sessionId, additionalData: additionalData)
    }
}

extension SessionState {
    fileprivate enum Keys: String {
        case creationDate = "creation_date"
        case expirationDate = "expiration_date"
        case sessionId = "session_id"
        case additionalData = "additional_data"
    }
}
