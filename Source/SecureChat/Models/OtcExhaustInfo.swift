//
//  OtcExhaustInfo.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/23/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

struct OtcExhaustInfo {
    let cardId: String
    let exhaustDate: Date
}

extension OtcExhaustInfo {
    private enum Keys: String {
        case cardId = "card_id"
        case exhaustDate = "exhaust_date"
    }
    
    func encode() -> [String : Any] {
        let dict: [String : Any] = [
            Keys.cardId.rawValue: self.cardId,
            Keys.exhaustDate.rawValue: self.exhaustDate.timeIntervalSince1970
        ]
        
        return dict
    }
    
    init?(dict: [String : Any]) {
        guard let cardId = dict[Keys.cardId.rawValue] as? String,
            let exhaustDateInterval = dict[Keys.exhaustDate.rawValue] as? TimeInterval else {
                return nil
        }
        
        self.init(cardId: cardId, exhaustDate: Date(timeIntervalSince1970: exhaustDateInterval))
    }
}

