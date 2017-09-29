//
//  ServiceConfig.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/15/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

@objc(VSPServiceConfig) class ServiceConfig: NSObject {
    @objc let token: String
    @objc let ephemeralServiceURL: URL
    
    @objc init(token: String, ephemeralServiceURL: URL? = nil) {
        self.token = token
        self.ephemeralServiceURL = ephemeralServiceURL ?? URL(string: "https://pfs.virgilsecurity.com/v1/")!
        
        super.init()
    }
}
