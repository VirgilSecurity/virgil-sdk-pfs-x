//
//  CredentialsHTTPRequest.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/15/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

class CredentialsHTTPRequest: PFSBaseHTTPRequest {
    private(set) var credentialsResponse: CredentialsCollectionResponse?
    
    init(context: VSSHTTPRequestContext, credentialsRequest: CredentialsRequest) {
        super.init(context: context)
        
        self.setRequestBodyWith(credentialsRequest.serialize())
    }
    
    override var methodPath: String {
        return "recipient/actions/search-by-ids"
    }
    
    override func handleResponse(_ candidate: NSObject?) -> Error? {
        guard let candidate = candidate else {
            return nil
        }
        
        let error = super.handleResponse(candidate)
        
        guard error == nil else {
            return error
        }
        
        
        self.credentialsResponse = CredentialsCollectionResponse(dictionary: candidate)
        
        return nil
    }
}
