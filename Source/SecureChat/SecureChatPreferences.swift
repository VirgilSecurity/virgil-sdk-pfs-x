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
    public let numberOfActiveOneTimeCards: Int
    public let deviceManager: VSSDeviceManagerProtocol
    
    public init(myCardId: String, myPrivateKey: VSSPrivateKey, crypto: VSSCryptoProtocol, keyStorage: VSSKeyStorageProtocol, serviceConfig: ServiceConfig, virgilServiceConfig: VSSServiceConfig, numberOfActiveOneTimeCards: Int, deviceManager: VSSDeviceManagerProtocol) {
        self.myCardId = myCardId
        self.myPrivateKey = myPrivateKey
        self.crypto = crypto
        self.keyStorage = keyStorage
        self.serviceConfig = serviceConfig
        self.virgilServiceConfig = virgilServiceConfig
        self.numberOfActiveOneTimeCards = numberOfActiveOneTimeCards
        self.deviceManager = deviceManager
    }
    
    convenience public init(myCardId: String, myPrivateKey: VSSPrivateKey, accessToken: String) {
        self.init(myCardId: myCardId, myPrivateKey: myPrivateKey, crypto: VSSCrypto(), keyStorage: VSSKeyStorage(), serviceConfig: ServiceConfig(token: accessToken), virgilServiceConfig: VSSServiceConfig(token: accessToken), numberOfActiveOneTimeCards: 100, deviceManager: VSSDeviceManager())
    }
}
