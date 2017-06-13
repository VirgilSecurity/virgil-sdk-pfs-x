//
//  BootstrapCardsResponse.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

struct BootstrapCardsResponse {
    let ltc: String
    let otc: [String]
    
    fileprivate init(ltc: String, otc: [String]) {
        self.ltc = ltc
        self.otc = otc
    }
}

extension BootstrapCardsRequest: Deserializable {
    init?(dictionary: Any) {
        guard let dictionary = dictionary as? [String: Any] else {
            return nil
        }
        
        guard let ltc = dictionary["long_time_card"] as? String,
            let otc = dictionary["one_time_cards"] as? [String] else {
                return nil
        }
        
        self.init(ltc: ltc, otc: otc)
    }
}
