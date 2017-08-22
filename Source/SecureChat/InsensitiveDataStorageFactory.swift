//
//  InsensitiveDataStorageFactory.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/23/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

@objc(VSPInsensitiveDataStorageFactory) public protocol InsensitiveDataStorageFactory {
    func makeStorage(forIdentifier identifier: String) throws -> InsensitiveDataStorage
}
