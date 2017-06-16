//
//  BootstrapCardsRequest.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

struct BootstrapCardsRequest {
    let ltc: [AnyHashable: Any]
    let otc: [[AnyHashable: Any]]
}

extension BootstrapCardsRequest: Serializable {
    func serialize() -> NSObject {
        let dict: NSDictionary = [
            "long_time_card": self.ltc,
            "one_time_cards": self.otc
        ]
        
        return dict
    }
}
