//
//  KeyEntry.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

@objc(VSPKeyEntry) public class KeyEntry: NSObject {
    let name: String
    let value: Data
    
    init(name: String, value: Data) {
        self.name = name
        self.value = value
        
        super.init()
    }
}
