//
//  UploadOtcResponse.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

struct UploadOtcResponse {
    let otc: [String]
    
    fileprivate init(otc: [String]) {
        self.otc = otc
    }
}

extension UploadOtcResponse: Deserializable {
    init?(dictionary: Any) {
        guard let otc = dictionary as? [String] else {
            return nil
        }
        
        self.init(otc: otc)
    }
}
