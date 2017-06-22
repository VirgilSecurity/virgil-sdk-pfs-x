//
//  ServiceInfoEntry.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/21/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

class ServiceInfoEntry: NSObject, NSCoding {
    private enum Keys: String {
        case otcKeysNames = "otc_keys_names"
        case ltcKeyName = "ltc_key_name"
    }
    
    let otcKeysNames: [String]
    let ltcKeyName: String
    
    init(ltcKeyName: String, otcKeysNames: [String]) {
        self.otcKeysNames = otcKeysNames
        self.ltcKeyName = ltcKeyName
        
        super.init()
    }
    
    func encode(with aCoder: NSCoder) {
        aCoder.encode(self.ltcKeyName, forKey: Keys.ltcKeyName.rawValue)
        aCoder.encode(self.otcKeysNames, forKey: Keys.otcKeysNames.rawValue)
    }
    
    convenience required init?(coder aDecoder: NSCoder) {
        guard let ltcKeyName = aDecoder.decodeObject(forKey: Keys.ltcKeyName.rawValue) as? String,
            let otcKeysNames = aDecoder.decodeObject(forKey: Keys.otcKeysNames.rawValue) as? [String] else {
                return nil
        }
        
        self.init(ltcKeyName: ltcKeyName, otcKeysNames: otcKeysNames)
    }
}
