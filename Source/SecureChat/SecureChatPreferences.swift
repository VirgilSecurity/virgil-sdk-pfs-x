//
//  SecureChatPreferences.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/20/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

@objc(VSPSecureChatPreferences) public class SecureChatPreferences: NSObject {
    public let myCardId: String
    public let myPrivateKey: VSSPrivateKey
    public let crypto: VSSCryptoProtocol
    public let keyStorage: VSSKeyStorageProtocol
    public let serviceConfig: ServiceConfig
    public let virgilServiceConfig: VSSServiceConfig
    
    public init(myCardId: String, myPrivateKey: VSSPrivateKey, crypto: VSSCryptoProtocol, keyStorage: VSSKeyStorageProtocol, serviceConfig: ServiceConfig, virgilServiceConfig: VSSServiceConfig) {
        self.myCardId = myCardId
        self.myPrivateKey = myPrivateKey
        self.crypto = crypto
        self.keyStorage = keyStorage
        self.serviceConfig = serviceConfig
        self.virgilServiceConfig = virgilServiceConfig
    }
    
    convenience init(myCardId: String, myPrivateKey: VSSPrivateKey, crypto: VSSCryptoProtocol, keyStorage: VSSKeyStorageProtocol, accessToken: String) {
        self.init(myCardId: myCardId, myPrivateKey: myPrivateKey, crypto: crypto, keyStorage: keyStorage, serviceConfig: ServiceConfig(token: accessToken), virgilServiceConfig: VSSServiceConfig(token: accessToken))
    }
}
