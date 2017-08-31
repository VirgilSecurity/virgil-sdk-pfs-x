//
//  UserDefaultsDataStorage.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

/// InsensitiveDataStorage implementation usign UserDefaults with separate suite
@objc(VSPUserDefaultsDataStorage) public class UserDefaultsDataStorage: NSObject, InsensitiveDataStorage {
    private let userDefaults: UserDefaults
    
    /// Error domain for NSError instances thrown from here
    public static let ErrorDomain = "VSPUserDefaultsDataStorageErrorDomain"
    
    private static let SuiteNameFormat = "VIRGIL.DEFAULTS.%@"
    
    private class func getSuiteName(forIdentifier identifier: String) -> String {
        return String(format: UserDefaultsDataStorage.SuiteNameFormat, identifier)
    }
    
    /// Factory method
    ///
    /// - Parameter identifier: identifier for storage (e.g. card identifier)
    /// - Returns: initialized storage
    /// - Throws: NSError instances with corresponding error description
    public class func makeStorage(forIdentifier identifier: String) throws -> UserDefaultsDataStorage {
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
    
    /// Stores value for given key
    ///
    /// - Parameters:
    ///   - value: value to store. NOTE: Value is dictionary which contains instances of array, dictionary, string, data, date classes and is not json serializable by-default
    ///   - key: key
    /// - Throws: NSError instances with corresponding description
    public func storeValue(_ value: Any?, forKey key: String) throws {
        self.userDefaults.set(value, forKey: key)
        CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication)
    }
    
    /// Loads value for given key
    ///
    /// - Parameter key: Leu
    /// - Returns: Loaded value
    public func loadValue(forKey key: String) -> Any? {
        return self.userDefaults.value(forKey: key)
    }
}
