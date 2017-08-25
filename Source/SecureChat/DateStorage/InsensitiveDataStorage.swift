//
//  InsensitiveDataStorage.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

@objc(VSPInsensitiveDataStorage) public protocol InsensitiveDataStorage {
    func loadValue(forKey key: String) -> Any?
    
    func storeValue(_ value: Any?, forKey defaultName: String) throws
    
    func removeValue(forKey key: String) throws
}
