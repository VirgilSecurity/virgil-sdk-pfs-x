//
//  CreateLtcResponse.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

final class CreateLtcResponse: NSObject, Deserializable {
    let ltc: [AnyHashable: Any]
    
    fileprivate init(ltc: [AnyHashable: Any]) {
        self.ltc = ltc
    }
    
    required convenience init?(dictionary: Any) {
        guard let ltc = dictionary as? [AnyHashable: Any] else {
            return nil
        }
        
        self.init(ltc: ltc)
    }
}
