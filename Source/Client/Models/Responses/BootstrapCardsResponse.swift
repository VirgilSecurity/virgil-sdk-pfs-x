//
//  BootstrapCardsResponse.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

class BootstrapCardsResponse: NSObject, Deserializable {
    let ltc: [AnyHashable: Any]
    let otc: [[AnyHashable: Any]]
    
    fileprivate init(ltc: [AnyHashable: Any], otc: [[AnyHashable: Any]]) {
        self.ltc = ltc
        self.otc = otc
    }
    
    required convenience init?(dictionary: Any) {
        guard let dictionary = dictionary as? [String: Any] else {
            return nil
        }
        
        guard let ltc = dictionary["long_time_card"] as? [AnyHashable: Any],
            let otc = dictionary["one_time_cards"] as? [[AnyHashable: Any]] else {
                return nil
        }
        
        self.init(ltc: ltc, otc: otc)
    }
}
