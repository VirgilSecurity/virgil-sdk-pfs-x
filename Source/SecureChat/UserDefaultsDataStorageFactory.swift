//
//  UserDefaultsDataStorageFactory.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/23/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

@objc(VSPUserDefaultsDataStorageFactory) public class UserDefaultsDataStorageFactory: NSObject, InsensitiveDataStorageFactory {
    static let SuiteNameFormat = "VIRGIL.DEFAULTS.%@"
    
    private func getSuiteName(forIdentifier identifier: String) -> String {
        return String(format: UserDefaultsDataStorageFactory.SuiteNameFormat, identifier)
    }
    
    public func makeStorage(forIdentifier identifier: String) throws -> InsensitiveDataStorage {
        let suiteName = self.getSuiteName(forIdentifier: identifier)
        
        guard let storage = UserDefaultsDataStorage(suiteName: suiteName) else {
            // FIXME
            throw NSError()
        }
        
        return storage
    }
}
