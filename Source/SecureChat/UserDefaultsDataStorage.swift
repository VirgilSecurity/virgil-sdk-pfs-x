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
    
    private static let RootKey = "ROOT_KEY"
    
    init?(suiteName: String) {
        guard let userDefaults = UserDefaults(suiteName: suiteName) else {
            return nil
        }
        
        self.userDefaults = userDefaults
        
        super.init()
    }
    
    public func storeValue(_ value: Any?, forKey key: String) throws {
        var dict = self.userDefaults.value(forKey: UserDefaultsDataStorage.RootKey) as? [String : Any] ?? [:]
        
        dict[key] = value
        
        self.userDefaults.set(dict, forKey: UserDefaultsDataStorage.RootKey)
        self.userDefaults.synchronize()
    }
    
    public func loadValue(forKey key: String) -> Any? {
        guard let dict = self.userDefaults.value(forKey: UserDefaultsDataStorage.RootKey) as? [String : Any] else {
            return nil
        }
        
        return dict[key]
    }
    
    public func removeValue(forKey key: String) throws {
        var dict = self.userDefaults.value(forKey: UserDefaultsDataStorage.RootKey) as? [String : Any] ?? [:]
        
        dict.removeValue(forKey: key)
        
        self.userDefaults.set(dict, forKey: UserDefaultsDataStorage.RootKey)
        self.userDefaults.synchronize()
    }
    
    public func removeValues(forKeys keys: [String]) throws {
        var dict = self.userDefaults.value(forKey: UserDefaultsDataStorage.RootKey) as? [String : Any]  ?? [:]
        
        for key in keys {
            dict.removeValue(forKey: key)
        }
        
        self.userDefaults.set(dict, forKey: UserDefaultsDataStorage.RootKey)
        self.userDefaults.synchronize()
    }

    public func getAllValues() -> [String : Any]? {
        return self.userDefaults.value(forKey: UserDefaultsDataStorage.RootKey) as? [String : Any]
    }
}
