//
//  ValidateOTCHTTPRequest.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/29/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

class ValidateOTCHTTPRequest: PFSBaseHTTPRequest {
    private(set) var validateOTCResponse: ValidateOTCResponse?
    let recipientId: String
    
    init(context: VSSHTTPRequestContext, recipientId: String, validateRequest: ValidateOTCRequest) {
        self.recipientId = recipientId
        
        super.init(context: context)
        
        self.setRequestBodyWith(validateRequest.serialize())
    }
    
    override var methodPath: String {
        return "recipient/\(self.recipientId)/actions/validate-otcs"
    }
    
    override func handleResponse(_ candidate: NSObject?) -> Error? {
        guard let candidate = candidate else {
            return nil
        }
        
        let error = super.handleResponse(candidate)
        
        guard error == nil else {
            return error
        }
        
        
        self.validateOTCResponse = ValidateOTCResponse(dictionary: candidate)
        
        return nil
    }
}
