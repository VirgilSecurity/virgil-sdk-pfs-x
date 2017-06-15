//
//  OtcCountHTTPRequest.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/15/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

class OtcCountHTTPRequest: PFSBaseHTTPRequest {
    let recipientId: String
    
    private(set) var otcCountResponse: OtcCountResponse?
    
    init(context: VSSHTTPRequestContext, recipientId: String) {
        self.recipientId = recipientId
        
        super.init(context: context)
        
        self.setRequestMethod(.GET)
    }
    
    override var methodPath: String {
        return "recipient/" + self.recipientId + "/actions/count-otcs"
    }
    
    override func handleResponse(_ candidate: NSObject?) -> Error? {
        guard let candidate = candidate else {
            return nil
        }
        
        let error = super.handleResponse(candidate)
        
        guard error == nil else {
            return error
        }
        
        
        self.otcCountResponse = OtcCountResponse(dictionary: candidate)
        
        return nil
    }
}
