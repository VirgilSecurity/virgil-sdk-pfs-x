//
//  Client+Info.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/19/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

extension Client {
    func getCardsStatus(forUserWithCardId cardId: String, completion: @escaping ((CardsStatus?, Error?)->())) {
        let context = VSSHTTPRequestContext(serviceUrl: self.serviceConfig.ephemeralServiceURL)
        let httpRequest = OtcCountHTTPRequest(context: context, recipientId: cardId)
        
        let handler = { (request: VSSHTTPRequest) in
            guard request.error == nil else {
                completion(nil, request.error!)
                return
            }
            
            let request = request as! OtcCountHTTPRequest
            guard let response = request.otcCountResponse else {
                completion(nil, nil)
                return
            }
            
            completion(CardsStatus(active: response.active, exhausted: response.exhausted), nil)
        }
        
        httpRequest.completionHandler = handler
        
        self.send(httpRequest)
    }
}
