//
//  BootstrapCardsRequest.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

struct BootstrapCardsRequest {
    let ltc: String
    let otc: [String]
}

extension BootstrapCardsRequest: Serializable {
    func serialize() -> Any {
        return [
            "long_time_card": self.ltc,
            "one_time_cards": self.otc
        ]
    }
}
