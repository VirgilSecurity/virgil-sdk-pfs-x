//
//  ServiceInfoEntry.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/21/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

class ServiceInfoEntry: NSObject, NSCoding {
    private enum EncodingKeys: String {
        case otcKeysNames = "otc_keys_names"
    }
    
    let otcKeysNames: [String]
    
    init(otcKeysNames: [String]) {
        self.otcKeysNames = otcKeysNames
        
        super.init()
    }
    
    func encode(with aCoder: NSCoder) {
        aCoder.encode(self.otcKeysNames, forKey: EncodingKeys.otcKeysNames.rawValue)
    }
    
    convenience required init?(coder aDecoder: NSCoder) {
        guard let otcKeysNames = aDecoder.decodeObject(forKey: EncodingKeys.otcKeysNames.rawValue) as? [String] else {
            return nil
        }
        
        self.init(otcKeysNames: otcKeysNames)
    }
}
