//
//  CredentialsResponse.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

final class CredentialsResponse: NSObject, Deserializable {
    let ltc: [AnyHashable: Any]
    let otc: [AnyHashable: Any]?
    
    fileprivate init(ltc: [AnyHashable: Any], otc: [AnyHashable: Any]?) {
        self.ltc = ltc
        self.otc = otc
    }
    
    required convenience init?(dictionary: Any) {
        guard let dictionary = dictionary as? [String: Any] else {
            return nil
        }
        
        guard let ltc = dictionary["long_time_card"] as? [AnyHashable: Any] else {
            return nil
        }
        
        self.init(ltc: ltc, otc: dictionary["one_time_card"] as? [AnyHashable: Any])
    }
}

final class CredentialsCollectionResponse: NSObject, Deserializable {
    let credentials: [CredentialsResponse]
    
    fileprivate init(credentials: [CredentialsResponse]) {
        self.credentials = credentials
    }
    
    required convenience init?(dictionary: Any) {
        guard let dictionary = dictionary as? [[AnyHashable: Any]] else {
            return nil
        }
        
        var credentialsArr: [CredentialsResponse] = []
        credentialsArr.reserveCapacity(dictionary.count)
        
        for dict in dictionary {
            guard let credentials = CredentialsResponse(dictionary: dict) else {
                return nil
            }
            
            credentialsArr.append(credentials)
        }
        
        self.init(credentials: credentialsArr)
    }
}
