//
//  Client+GetCredentials.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/19/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

extension Client {
    func getRecipientCardsSet(forCardsIds cardsIds: [String], completion: @escaping (([RecipientCardsSet]?, Error?)->())) {
        let context = VSSHTTPRequestContext(serviceUrl: self.serviceConfig.ephemeralServiceURL)
        let request = CredentialsRequest(cardsIds: cardsIds)
        let httpRequest = CredentialsHTTPRequest(context: context, credentialsRequest: request)
        
        let handler = { (request: VSSHTTPRequest) in
            guard request.error == nil else {
                completion(nil, request.error!)
                return
            }
            
            let request = request as! CredentialsHTTPRequest
            guard let response = request.credentialsResponse,
                response.credentials.count > 0 else {
                    completion(nil, nil)
                    return
            }
            
            var credentials: [RecipientCardsSet] = []
            credentials.reserveCapacity(response.credentials.count)
            
            for cred in response.credentials {
                guard let ltc = VSSCard(dict: cred.ltc) else {
                        completion(nil, nil)
                        return
                }
                
                let otc = cred.otc != nil ? VSSCard(dict: cred.otc!) : nil
                
                credentials.append(RecipientCardsSet(longTermCard: ltc, oneTimeCard: otc))
            }
            
            completion(credentials, nil)
        }
        
        httpRequest.completionHandler = handler
        
        self.send(httpRequest)
    }
}
