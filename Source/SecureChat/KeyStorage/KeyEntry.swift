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
    @objc public let name: String
    
    /// Key raw value
    @objc public let value: Data
    
    /// Initialized
    ///
    /// - Parameters:
    ///   - name: key name
    ///   - value: key raw data
    @objc public init(name: String, value: Data) {
        self.name = name
        self.value = value
        
        super.init()
    }
}
