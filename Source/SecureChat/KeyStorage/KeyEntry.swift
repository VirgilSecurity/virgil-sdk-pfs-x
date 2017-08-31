//
//  KeyEntry.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

/// Class for representing key entry info
@objc(VSPKeyEntry) public class KeyEntry: NSObject {
    /// Key name
    public let name: String
    
    /// Key raw value
    public let value: Data
    
    /// Initialized
    ///
    /// - Parameters:
    ///   - name: key name
    ///   - value: key raw data
    public init(name: String, value: Data) {
        self.name = name
        self.value = value
        
        super.init()
    }
}
