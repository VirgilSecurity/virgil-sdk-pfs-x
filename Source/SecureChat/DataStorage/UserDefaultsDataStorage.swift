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
        
        guard dict.removeValue(forKey: key) != nil else {
            throw NSError(domain: UserDefaultsDataStorage.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while removing value for key. Value doesn't exist."])
        }
        
        self.userDefaults.set(dict, forKey: UserDefaultsDataStorage.RootKey)
        self.userDefaults.synchronize()
    }
    
    public func removeValues(forKeys keys: [String]) throws {
        var dict = self.userDefaults.value(forKey: UserDefaultsDataStorage.RootKey) as? [String : Any]  ?? [:]
        
        for key in keys {
            guard dict.removeValue(forKey: key) != nil else {
                throw NSError(domain: UserDefaultsDataStorage.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while removing value for key. Value doesn't exist."])
            }
        }
        
        self.userDefaults.set(dict, forKey: UserDefaultsDataStorage.RootKey)
        self.userDefaults.synchronize()
    }

    public func getAllValues() -> [String : Any]? {
        return self.userDefaults.value(forKey: UserDefaultsDataStorage.RootKey) as? [String : Any]
    }
}
