//
//  BootstrapCardsHTTPRequest.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

class BootstrapCardsHTTPRequest: PFSBaseHTTPRequest {
    let recipientId: String
    
    private(set) var bootstrapCardsResponse: BootstrapCardsResponse?
    
    init(context: VSSHTTPRequestContext, recipientId: String, request: BootstrapCardsRequest) {
        self.recipientId = recipientId
        
        super.init(context: context)
        
        self.setRequestMethod(.PUT)
        self.setRequestBodyWith(request.serialize())
    }
    
    override var methodPath: String {
        return "recipient/" + self.recipientId
    }
    
    override func handleResponse(_ candidate: NSObject?) -> Error? {
        guard let candidate = candidate else {
            return nil
        }
        
        let error = super.handleResponse(candidate)
        
        guard error == nil else {
            return error
        }
        
        self.bootstrapCardsResponse = BootstrapCardsResponse(dictionary: candidate)
        
        return nil
    }
}
