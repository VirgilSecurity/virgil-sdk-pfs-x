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
    let ephKeyName: String
}

extension ResponderSessionState: Serializable {
    func serialize() -> NSObject {
        let dict: NSDictionary = [
            Keys.creationDate.rawValue: self.creationDate,
            Keys.ephKeyName.rawValue: self.ephKeyName,
        ]
        
        return dict
    }
}

extension ResponderSessionState: Deserializable {
    init?(dictionary: Any) {
        guard let dict = dictionary as? [AnyHashable: Any] else {
            return nil
        }
        
        guard let date = dict[Keys.creationDate] as? Date,
            let ephKeyName = dict[Keys.ephKeyName.rawValue] as? String else {
                return nil
        }
        
        self.init(creationDate: date, ephKeyName: ephKeyName)
    }
}

extension ResponderSessionState {
    fileprivate enum Keys: String {
        case creationDate = "creationDate"
        case ephKeyName = "eph_key_name"
    }
}
