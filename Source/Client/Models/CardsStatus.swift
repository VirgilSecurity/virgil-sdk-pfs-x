//
//  CardsStatus.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/19/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

@objc(VSPCardsStatus) final class CardsStatus: NSObject {
    @objc let active: Int
    
    init(active: Int) {
        self.active = active
    }
}
