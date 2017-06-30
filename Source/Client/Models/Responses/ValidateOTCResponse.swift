//
//  ValidateOTCResponse.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/29/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

final class ValidateOTCResponse: NSObject, Deserializable {
    let exhaustedCardsIds: [String]
    
    fileprivate init(exhaustedCardsIds: [String]) {
        self.exhaustedCardsIds = exhaustedCardsIds
    }
    
    required convenience init?(dictionary: Any) {
        guard let dictionary = dictionary as? [String: Any] else {
            return nil
        }
        
        guard let exhaustedCardsIds = dictionary["exhausted_one_time_cards_ids"] as? [String] else {
            return nil
        }
        
        self.init(exhaustedCardsIds: exhaustedCardsIds)
    }
}
