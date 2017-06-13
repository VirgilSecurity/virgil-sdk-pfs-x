//
//  UploadOtcRequest.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

final class UploadOtcRequest: NSObject {
    let otc: [String]
    
    init(otc: [String]) {
        self.otc = otc
    }
}

extension UploadOtcRequest: Serializable {
    func serialize() -> Any {
        return self.otc
    }
}
