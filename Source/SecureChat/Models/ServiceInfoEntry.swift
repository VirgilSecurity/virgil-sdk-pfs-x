//
//  ServiceInfoEntry.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/21/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

class ServiceInfoEntry: NSObject {
    class KeyEntry: NSObject {
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
        
        func encode() -> [String : Any] {
            let json: [String : Any] = [
                Keys.keyName.rawValue: self.keyName,
                Keys.date.rawValue: self.date.timeIntervalSince1970
            ]
            
            return json
        }
        
        convenience init?(json: [String : Any]) {
            guard let keyName = json[Keys.keyName.rawValue] as? String,
                let dateInterval = json[Keys.date.rawValue] as? TimeInterval else {
                    return nil
            }
            
            self.init(keyName: keyName, date: Date(timeIntervalSince1970: dateInterval))
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
    
    func encode() throws -> Data {
        let json: [String : Any] = [
            Keys.otcKeysNames.rawValue: self.otcKeysNames,
            Keys.ephKeysNames.rawValue: self.ephKeysNames,
            Keys.ltcKeys.rawValue: self.ltcKeys.map({ $0.encode() })
        ]
        
        let jsonData = try JSONSerialization.data(withJSONObject: json, options: [])
        
        return jsonData
    }
    
    convenience init?(json: [String : Any]) {
        guard let otcKeysNames = json[Keys.otcKeysNames.rawValue] as? [String],
            let ephKeysNames = json[Keys.ephKeysNames.rawValue] as? [String],
            let ltcs = json[Keys.ltcKeys.rawValue] as? [[String : Any]] else {
                return nil
        }
        
        var ltcKeys = [KeyEntry]()
        ltcKeys.reserveCapacity(ltcs.count)
        
        for ltc in ltcs {
            guard let ketEntry = KeyEntry(json: ltc) else {
                return nil
            }
            
            ltcKeys.append(ketEntry)
        }
        
        self.init(ltcKeys: ltcKeys, otcKeysNames: otcKeysNames, ephKeysNames: ephKeysNames)
    }
    
    convenience init?(data: Data) {
        guard case let json?? = try? JSONSerialization.jsonObject(with: data, options: []) as? [String : Any] else {
            return nil
        }
        
        self.init(json: json)
    }
}
