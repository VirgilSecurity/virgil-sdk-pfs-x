//
//  InsensitiveDataStorage.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

/// Protocol for insensitive data storage for PFS
@objc(VSPInsensitiveDataStorage) public protocol InsensitiveDataStorage {
    /// Loads value for given key
    ///
    /// - Parameter key: Leu
    /// - Returns: Loaded value
    func loadValue(forKey key: String) -> Any?
    
    /// Stores value for given key
    ///
    /// - Parameters:
    ///   - value: value to store. NOTE: Value is dictionary which contains instances of array, dictionary, string, data, date classes and is not json serializable by-default
    ///   - key: key
    /// - Throws: NSError instances with corresponding description
    func storeValue(_ value: Any?, forKey key: String) throws
}
