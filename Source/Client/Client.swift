//
//  Client.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/15/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

@objc(VSPClient) class Client: VSSBaseClient {
    static let ErrorDomain = "VSPClientErrorDomain"
    
    private(set) var serviceConfig: ServiceConfig
    
    @objc init(serviceConfig: ServiceConfig) {
        self.serviceConfig = serviceConfig
        
        super.init()
    }
    
    @objc convenience init(token: String) {
        self.init(serviceConfig: ServiceConfig(token: token))
    }
    
    @objc override func send(_ request: VSSHTTPRequest) {
        if !self.serviceConfig.token.isEmpty {
            request.setRequestHeaders(["Authorization": String(format: "VIRGIL %@", self.serviceConfig.token)])
        }
        
        super.send(request)
    }
}
