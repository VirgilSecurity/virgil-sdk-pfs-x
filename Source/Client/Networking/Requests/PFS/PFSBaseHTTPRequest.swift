//
//  PFSBaseHTTPRequest.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

class PFSBaseHTTPRequest: VSSHTTPJSONRequest {
    override func handleError(_ candidate: NSObject?, code: Int) -> Error? {
        if let error = super.handleError(candidate, code: code) {
            return error
        }
        
        if let candidate = candidate {
            if let pfsError = PFSError(dictionary: candidate) {
                return pfsError.nsError
            }
            else if let candidate = candidate as? [AnyHashable: Any],
                let cardsError = VSSCardsError(dict: candidate) {
                return cardsError.nsError()
            }
        }
        
        return nil
    }
}
