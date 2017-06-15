//
//  Client.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/15/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

@objc(VSPClient) public class Client: VSSBaseClient {
    public func createEntry(forRecipientWithCardId cardId: String, longTermCard: VSSCreateUserCardRequest, oneTimeCards: [VSSCreateUserCardRequest], completion: @escaping ((VSSCard?, [VSSCard]?, Error?)->())) {
        // FIXME
        let context = VSSHTTPRequestContext(serviceUrl: URL(string: "")!)
        let httpRequest = BootstrapCardsHTTPRequest(context: context, recipientId: cardId, ltc: longTermCard.exportData(), otc: oneTimeCards.map({ $0.exportData() }))
        
        let handler = { (request: VSSHTTPRequest) in
            guard request.error == nil else {
                completion(nil, nil, request.error!)
                return
            }
            
            let request = request as! BootstrapCardsHTTPRequest
            guard let response = request.bootstrapCardsResponse else {
                completion(nil, nil, nil)
                return
            }
            
            do {
                let otc = try response.otc.map( { str -> VSSCard in
                    guard let card = VSSCard(data: str) else {
                        throw NSError()
                    }
                    
                    return card
                })
                
                guard let ltc = VSSCard(data: response.ltc) else {
                    completion(nil, nil, nil)
                    return
                }
                
                // FIXME: add validation
                completion(ltc, otc, nil)
                return
            }
            catch {
                completion(nil, nil, nil)
                return
            }
        }
        
        httpRequest.completionHandler = handler
        
        self.send(httpRequest)
    }
}
