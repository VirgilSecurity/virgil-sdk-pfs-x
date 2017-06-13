//
//  UploadOtcRequest.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

struct UploadOtcRequest {
    let otc: [String]
}

extension UploadOtcRequest: Serializable {
    func serialize() -> Any {
        return self.otc
    }
}
