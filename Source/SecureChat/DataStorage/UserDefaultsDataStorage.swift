//
//  UserDefaultsDataStorage.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

@objc(VSPUserDefaultsDataStorage) public class UserDefaultsDataStorage: NSObject, InsensitiveDataStorage {
    private let userDefaults: UserDefaults
    
    public static let ErrorDomain = "VSPUserDefaultsDataStorageErrorDomain"
    
    private static let SuiteNameFormat = "VIRGIL.DEFAULTS.%@"
    
    private class func getSuiteName(forIdentifier identifier: String) -> String {
        return String(format: UserDefaultsDataStorage.SuiteNameFormat, identifier)
    }
    
    public class func makeStorage(forIdentifier identifier: String) throws -> InsensitiveDataStorage {
        let suiteName = self.getSuiteName(forIdentifier: identifier)
        
        guard let storage = UserDefaultsDataStorage(suiteName: suiteName) else {
            throw NSError(domain: UserDefaultsDataStorage.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while instantiating storage."])
        }
        
        return storage
    }
    
    init?(suiteName: String) {
        guard let userDefaults = UserDefaults(suiteName: suiteName) else {
            return nil
        }
        
        self.userDefaults = userDefaults
        
        super.init()
    }
    
    public func storeValue(_ value: Any?, forKey key: String) throws {
        self.userDefaults.set(value, forKey: key)
        self.userDefaults.synchronize()
    }
    
    public func loadValue(forKey key: String) -> Any? {
        return self.userDefaults.value(forKey: key)
    }
}
