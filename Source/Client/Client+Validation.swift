//
//  Client+Validation.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/29/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

extension Client {
    public func validateOneTimeCards(forRecipientWithId recipientId: String, cardsIds: [String], completion: @escaping (([String]?, Error?)->())) {
        // FIXME
        guard cardsIds.count > 0 else {
            completion([], nil)
            return
        }
        
        let context = VSSHTTPRequestContext(serviceUrl: self.serviceConfig.ephemeralServiceURL)
        let request = ValidateOTCRequest(cardsIds: cardsIds)
        let httpRequest = ValidateOTCHTTPRequest(context: context, recipientId: recipientId, validateRequest: request)
        
        let handler = { (request: VSSHTTPRequest) in
            guard request.error == nil else {
                completion(nil, request.error!)
                return
            }
            
            let request = request as! ValidateOTCHTTPRequest
            guard let response = request.validateOTCResponse else {
                completion(nil, nil)
                return
            }
            
            completion(response.exhaustedCardsIds, nil)
        }
        
        httpRequest.completionHandler = handler
        
        self.send(httpRequest)
    }
}
