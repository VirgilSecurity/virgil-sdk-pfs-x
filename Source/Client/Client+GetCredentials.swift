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
    public func getRecipientCardsSet(forIdentities identities: [String], completion: @escaping (([RecipientCardsSet]?, Error?)->())) {
        let context = VSSHTTPRequestContext(serviceUrl: self.serviceConfig.ephemeralServiceURL)
        let request = CredentialsRequest(identities: identities)
        let httpRequest = CredentialsHTTPRequest(context: context, credentialsRequest: request)
        
        let handler = { (request: VSSHTTPRequest) in
            guard request.error == nil else {
                completion(nil, request.error!)
                return
            }
            
            let request = request as! CredentialsHTTPRequest
            guard let response = request.credentialsResponse else {
                completion(nil, nil)
                return
            }
            
            var credentials: [RecipientCardsSet] = []
            credentials.reserveCapacity(response.credentials.count)
            
            for cred in response.credentials {
                guard let ic = VSSCard(dict: cred.ic),
                    let ltc = VSSCard(dict: cred.ltc),
                    let otc = VSSCard(dict: cred.otc) else {
                        completion(nil, nil)
                        return
                }
                
                credentials.append(RecipientCardsSet(identityCard: ic, longTermCard: ltc, oneTimeCard: otc))
            }
            
            completion(credentials, nil)
        }
        
        httpRequest.completionHandler = handler
        
        self.send(httpRequest)
    }
}
