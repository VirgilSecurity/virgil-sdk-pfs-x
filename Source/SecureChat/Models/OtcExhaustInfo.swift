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
            Keys.exhaustDate.rawValue: self.exhaustDate
        ]
        
        return dict
    }
    
    init?(dict: [String : Any]) {
        guard let cardId = dict[Keys.cardId.rawValue] as? String,
            let exhaustDate = dict[Keys.exhaustDate.rawValue] as? Date else {
                return nil
        }
        
        self.init(cardId: cardId, exhaustDate: exhaustDate)
    }
}

extension OtcExhaustInfo: Equatable {
    static func ==(lhs: OtcExhaustInfo, rhs: OtcExhaustInfo) -> Bool {
        return lhs.cardId == rhs.cardId
            && lhs.exhaustDate == rhs.exhaustDate
    }
}
