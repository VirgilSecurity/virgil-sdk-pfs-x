//
//  KeyAttrs.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/23/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

@objc(VSPKeyAttrs) public class KeyAttrs: NSObject {
    let name: String
    let creationDate: Date
    
    init(name: String, creationDate: Date) {
        self.name = name
        self.creationDate = creationDate
        
        super.init()
    }
}
