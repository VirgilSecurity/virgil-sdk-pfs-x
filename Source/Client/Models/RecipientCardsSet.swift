//
//  RecipientCardsSet.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/19/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

@objc(VSPRecipientCardsSet) final class RecipientCardsSet: NSObject {
    let longTermCard: VSSCard
    let oneTimeCard: VSSCard?
    
    init(longTermCard: VSSCard, oneTimeCard: VSSCard?) {
        self.longTermCard = longTermCard
        self.oneTimeCard = oneTimeCard
        
        super.init()
    }
}
