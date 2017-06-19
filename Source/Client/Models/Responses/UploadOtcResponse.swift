//
//  UploadOtcResponse.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

final class UploadOtcResponse: NSObject, Deserializable {
    let otc: [[AnyHashable: Any]]
    
    fileprivate init(otc: [[AnyHashable: Any]]) {
        self.otc = otc
    }
    
    required convenience init?(dictionary: Any) {
        guard let otc = dictionary as? [[AnyHashable: Any]] else {
            return nil
        }
        
        self.init(otc: otc)
    }
}
