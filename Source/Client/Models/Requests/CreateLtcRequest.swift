//
//  CreateLtcRequest.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

struct CreateLtcRequest {
    let ltc: String
    
    init(ltc: String) {
        self.ltc = ltc
    }
}

extension CreateLtcRequest: Serializable {
    func serialize() -> Any {
        return self.ltc
    }
}
