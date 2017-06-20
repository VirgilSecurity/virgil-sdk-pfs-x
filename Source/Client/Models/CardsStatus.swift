//
//  CardsStatus.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/19/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

@objc(VSPCardsStatus) public final class CardsStatus: NSObject {
    public let active: Int
    public let exhausted: Int
    
    init(active: Int, exhausted: Int) {
        self.active = active
        self.exhausted = exhausted
    }
}
