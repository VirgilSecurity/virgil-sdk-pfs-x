//
//  CredentialsResponse.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

final class CredentialsResponse: NSObject, Deserializable {
    let ic: String
    let ltc: String
    let otc: String
    
    fileprivate init(ic: String, ltc: String, otc: String) {
        self.ic = ic
        self.ltc = ltc
        self.otc = otc
    }
    
    required convenience init?(dictionary: Any) {
        guard let dictionary = dictionary as? [String: Any] else {
            return nil
        }
        
        guard let ic = dictionary["identity_card"] as? String,
            let ltc = dictionary["long_time_card"] as? String,
            let otc = dictionary["one_time_cards"] as? String else {
                return nil
        }
        
        self.init(ic: ic, ltc: ltc, otc: otc)
    }
}

final class CredentialsCollectionResponse: NSObject, Deserializable {
    let ltc: String
    let otc: [String]
    
    fileprivate init(ltc: String, otc: [String]) {
        self.ltc = ltc
        self.otc = otc
    }
    
    required convenience init?(dictionary: Any) {
        guard let dictionary = dictionary as? [String: Any] else {
            return nil
        }
        
        guard let ltc = dictionary["long_time_card"] as? String,
            let otc = dictionary["one_time_cards"] as? [String] else {
                return nil
        }
        
        self.init(ltc: ltc, otc: otc)
    }
}
