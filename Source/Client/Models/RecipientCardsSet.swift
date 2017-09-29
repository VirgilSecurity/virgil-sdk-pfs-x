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
    @objc let longTermCard: VSSCard
    @objc let oneTimeCard: VSSCard?
    
    @objc init(longTermCard: VSSCard, oneTimeCard: VSSCard?) {
        self.longTermCard = longTermCard
        self.oneTimeCard = oneTimeCard
        
        super.init()
    }
}
