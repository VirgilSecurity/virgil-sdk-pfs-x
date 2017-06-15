//
//  CreateLtcHTTPRequest.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/15/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

class CreateLtcHTTPRequest: PFSBaseHTTPRequest {
    let recipientId: String
    let ltc: String
    
    private(set) var createLtcResponse: CreateLtcResponse?
    
    init(context: VSSHTTPRequestContext, recipientId: String, ltc: String) {
        self.recipientId = recipientId
        self.ltc = ltc
        
        super.init(context: context)
    }
    
    override var methodPath: String {
        return "recipient/" + self.recipientId + "/actions/push-ltc"
    }
    
    override func handleResponse(_ candidate: NSObject?) -> Error? {
        guard let candidate = candidate else {
            return nil
        }
        
        let error = super.handleResponse(candidate)
        
        guard error == nil else {
            return error
        }
        
        
        self.createLtcResponse = CreateLtcResponse(dictionary: candidate)
        
        return nil
    }
}
