//
//  CreateLtcResponse.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

struct CreateLtcResponse {
    let ltc: String
    
    fileprivate init(ltc: String) {
        self.ltc = ltc
    }
}

extension CreateLtcResponse: Deserializable {
    init?(dictionary: Any) {
        guard let ltc = dictionary as? String else {
            return nil
        }
        
        self.init(ltc: ltc)
    }
}
