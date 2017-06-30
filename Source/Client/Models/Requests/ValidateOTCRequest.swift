//
//  ValidateOTCRequest.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/29/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

struct ValidateOTCRequest {
    let cardsIds: [String]
}

extension ValidateOTCRequest: Serializable {
    func serialize() -> NSObject {
        let dict: NSDictionary = [
            "one_time_cards_ids": self.cardsIds,
            ]
        
        return dict
    }
}
