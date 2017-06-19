//
//  CredentialsResponse.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/19/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

@objc(VSPCredentials) public final class Credentials: NSObject {
    public let identityCard: VSSCard
    public let longTermCard: VSSCard
    public let oneTimeCard: VSSCard
    
    init(identityCard: VSSCard, longTermCard: VSSCard, oneTimeCard: VSSCard) {
        self.identityCard = identityCard
        self.longTermCard = longTermCard
        self.oneTimeCard = oneTimeCard
        
        super.init()
    }
}
