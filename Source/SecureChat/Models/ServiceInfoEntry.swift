//
//  ServiceInfoEntry.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/21/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

@objc(VSPServiceInfoEntry) class ServiceInfoEntry: NSObject, NSCoding {
    @objc(VSPServiceInfoEntryKeyEntry) class KeyEntry: NSObject, NSCoding {
        private enum Keys: String {
            case keyName = "key_name"
            case date = "date"
        }
        
        let keyName: String
        let date: Date
        
        init(keyName: String, date: Date) {
            self.keyName = keyName
            self.date = date
            
            super.init()
        }
        
        func encode(with aCoder: NSCoder) {
            aCoder.encode(self.keyName, forKey: Keys.keyName.rawValue)
            aCoder.encode(self.date, forKey: Keys.date.rawValue)
        }
        
        convenience required init?(coder aDecoder: NSCoder) {
            guard let keyName = aDecoder.decodeObject(forKey: Keys.keyName.rawValue) as? String,
                let date = aDecoder.decodeObject(forKey: Keys.date.rawValue) as? Date else {
                    return nil
            }
            
            self.init(keyName: keyName, date: date)
        }
    }
    
    private enum Keys: String {
        case otcKeysNames = "otc_keys_names"
        case ltcKeys = "ltc_keys"
        case ephKeysNames = "eph_keys_names"
    }
    
    let otcKeysNames: [String]
    let ltcKeys: [KeyEntry]
    let ephKeysNames: [String]
    
    init(ltcKeys: [KeyEntry], otcKeysNames: [String], ephKeysNames: [String]) {
        self.otcKeysNames = otcKeysNames
        self.ltcKeys = ltcKeys
        self.ephKeysNames = ephKeysNames
        
        super.init()
    }
    
    func encode(with aCoder: NSCoder) {
        aCoder.encode(self.ltcKeys, forKey: Keys.ltcKeys.rawValue)
        aCoder.encode(self.otcKeysNames, forKey: Keys.otcKeysNames.rawValue)
        aCoder.encode(self.ephKeysNames, forKey: Keys.ephKeysNames.rawValue)
    }
    
    convenience required init?(coder aDecoder: NSCoder) {
        guard let ltcKeys = aDecoder.decodeObject(forKey: Keys.ltcKeys.rawValue) as? [KeyEntry],
            let otcKeysNames = aDecoder.decodeObject(forKey: Keys.otcKeysNames.rawValue) as? [String],
            let ephKeysNames = aDecoder.decodeObject(forKey: Keys.ephKeysNames.rawValue) as? [String] else {
                return nil
        }
        
        self.init(ltcKeys: ltcKeys, otcKeysNames: otcKeysNames, ephKeysNames: ephKeysNames)
    }
}
