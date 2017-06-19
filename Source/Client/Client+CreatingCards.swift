//
//  Client+CreatingCards.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/19/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

extension Client {
    public func createEntry(forRecipientWithCardId cardId: String, longTermCardRequest: VSPCreateEphemeralCardRequest, oneTimeCardsRequests: [VSPCreateEphemeralCardRequest], completion: @escaping ((VSSCard?, [VSSCard]?, Error?)->())) {
        let context = VSSHTTPRequestContext(serviceUrl: self.serviceConfig.ephemeralServiceURL)
        let request = BootstrapCardsRequest(ltc: longTermCardRequest.serialize(), otc: oneTimeCardsRequests.map({ $0.serialize() }))
        let httpRequest = BootstrapCardsHTTPRequest(context: context, recipientId: cardId, request: request)
        
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
                let otc = try response.otc.map( { dict -> VSSCard in
                    guard let card = VSSCard(dict: dict) else {
                        throw NSError()
                    }
                    
                    return card
                })
                
                guard let ltc = VSSCard(dict: response.ltc) else {
                    completion(nil, nil, nil)
                    return
                }
                
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
    
    public func createLongTermCard(forRecipientWithCardId cardId: String, longTermCardRequest: VSPCreateEphemeralCardRequest, completion: @escaping ((VSSCard?, Error?)->())) {
        let context = VSSHTTPRequestContext(serviceUrl: self.serviceConfig.ephemeralServiceURL)
        let httpRequest = CreateLtcHTTPRequest(context: context, recipientId: cardId, ltc: longTermCardRequest.serialize())
        
        let handler = { (request: VSSHTTPRequest) in
            guard request.error == nil else {
                completion(nil, request.error!)
                return
            }
            
            let request = request as! CreateLtcHTTPRequest
            guard let response = request.createLtcResponse else {
                completion(nil, nil)
                return
            }
            
            guard let ltc = VSSCard(dict: response.ltc) else {
                completion(nil, nil)
                return
            }
            
            completion(ltc, nil)
            return
        }
        
        httpRequest.completionHandler = handler
        
        self.send(httpRequest)
    }
    
    public func createOneTimeCards(forRecipientWithCardId cardId: String, oneTimeCardsRequests: [VSPCreateEphemeralCardRequest], completion: @escaping (([VSSCard]?, Error?)->())) {
        let context = VSSHTTPRequestContext(serviceUrl: self.serviceConfig.ephemeralServiceURL)
        let httpRequest = UploadOtcHTTPRequest(context: context, recipientId: cardId, otc: oneTimeCardsRequests.map({ $0.serialize() }))
        
        let handler = { (request: VSSHTTPRequest) in
            guard request.error == nil else {
                completion(nil, request.error!)
                return
            }
            
            let request = request as! UploadOtcHTTPRequest
            guard let response = request.uploadOtcResponse else {
                completion(nil, nil)
                return
            }
            
            do {
                let otc = try response.otc.map( { dict -> VSSCard in
                    guard let card = VSSCard(dict: dict) else {
                        throw NSError()
                    }
                    
                    return card
                })
                
                completion(otc, nil)
                return
            }
            catch {
                completion(nil, nil)
                return
            }
        }
        
        httpRequest.completionHandler = handler
        
        self.send(httpRequest)
    }
}
