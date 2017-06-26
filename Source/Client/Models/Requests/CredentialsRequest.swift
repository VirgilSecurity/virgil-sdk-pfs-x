//
//  CredentialsRequest.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/20/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

struct CredentialsRequest {
    let cardsIds: [String]
}

extension CredentialsRequest: Serializable {
    func serialize() -> NSObject {
        let dict: NSDictionary = [
            "identity_cards_ids": self.cardsIds,
        ]
        
        return dict
    }
}
