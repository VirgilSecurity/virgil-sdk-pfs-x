//
//  KeyAttrs.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/23/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

/// Class for representing key attributes info
@objc(VSPKeyAttrs) public class KeyAttrs: NSObject {
    /// Key name
    public let name: String
    /// Key creation date
    public let creationDate: Date
    
    /// Initializer
    ///
    /// - Parameters:
    ///   - name: Key name
    ///   - creationDate: Key creation date
    public init(name: String, creationDate: Date) {
        self.name = name
        self.creationDate = creationDate
        
        super.init()
    }
}
