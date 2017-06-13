//
//  OtcCountResponse.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

final class OtcCountResponse: NSObject, Deserializable {
    let active: Int
    let exhausted: Int
    
    fileprivate init(active: Int, exhausted: Int) {
        self.active = active
        self.exhausted = exhausted
    }
    
    required convenience init?(dictionary: Any) {
        guard let dictionary = dictionary as? [String: Any] else {
            return nil
        }
        
        guard let active = dictionary["active"] as? NSNumber,
            let exhausted = dictionary["exhausted"] as? NSNumber else {
                return nil
        }
        
        self.init(active: active.intValue, exhausted: exhausted.intValue)
    }
}
