//
//  KeyStorageMock.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/31/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK
import VirgilSDKPFS

@objc(VSPKeyStorageMock) public class KeyStorageMock: NSObject, VSSKeyStorageProtocol {
    private var dict: [String : Data] = [:]
    private let fileURL: String
    
    private func dummyError() -> NSError {
        return NSError(domain: "", code: -1, userInfo: nil)
    }
    
    public init(name: String, data: Data? = nil) {
        let paths = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true)
        let documentsDirectory = paths[0]
        
        let fileURL = "\(documentsDirectory)/\(name).plist"
        
        self.fileURL = fileURL
        
        if let data = data,
            let dictionary = try! PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? NSDictionary,
            let dict = dictionary as? [String : Data] {
                self.dict = dict
        }
    }
    
    public func deleteKeyEntry(withName name: String) throws {
        guard self.dict.removeValue(forKey: name) != nil else {
            throw self.dummyError()
        }
    }

    public func existsKeyEntry(withName name: String) -> Bool {
        return self.dict[name] != nil
    }

    public func loadKeyEntry(withName name: String) throws -> VSSKeyEntry {
        guard let data = self.dict[name] else {
            throw self.dummyError()
        }
        
        guard let keyEntry = NSKeyedUnarchiver.unarchiveObject(with: data) as? VSSKeyEntry else {
            throw self.dummyError()
        }
        
        return keyEntry
    }

    public func store(_ keyEntry: VSSKeyEntry) throws {
        let data = NSKeyedArchiver.archivedData(withRootObject: keyEntry)
        self.dict[keyEntry.name] = data
    }
    
    public func dump() {
        let data = try! PropertyListSerialization.data(fromPropertyList: self.dict as NSDictionary, format: .xml, options: 0)
        FileManager().createFile(atPath: self.fileURL, contents: data, attributes: nil)
    }
}

class KeyStorageAdapter: KeyStorage {
    private let keyStorageMock: KeyStorageMock
    
    init(keyStorageMock: KeyStorageMock) {
        self.keyStorageMock = keyStorageMock
    }
    
    public func storeKeyEntry(_ keyEntry: KeyEntry) throws {
        try self.keyStorageMock.store(VSSKeyEntry(name: keyEntry.name, value: keyEntry.value))
    }
    
    public func storeKeyEntries(_ keyEntries: [KeyEntry]) throws {
        for keyEntry in keyEntries {
            try self.storeKeyEntry(keyEntry)
        }
    }
    
    public func loadKeyEntry(withName name: String) throws -> KeyEntry {
        let keyEntry = try self.keyStorageMock.loadKeyEntry(withName: name)
        return KeyEntry(name: keyEntry.name, value: keyEntry.value)
    }
    
    public func deleteKeyEntry(withName name: String) throws {
        try self.keyStorageMock.deleteKeyEntry(withName: name)
    }
    
    public func deleteKeyEntries(withNames names: [String]) throws {
        for name in names {
            try self.deleteKeyEntry(withName: name)
        }
    }
    
    public func getAllKeysAttrs() throws -> [KeyAttrs] {
        return []
    }
}
