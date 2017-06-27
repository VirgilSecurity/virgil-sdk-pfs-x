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
    public let deviceManager: VSSDeviceManagerProtocol
    public let numberOfActiveOneTimeCards: Int
    public let daysLongTermCardLives: Int
    public let sessionTtl: TimeInterval
    
    
    public init(myCardId: String, myPrivateKey: VSSPrivateKey, crypto: VSSCryptoProtocol, keyStorage: VSSKeyStorageProtocol, serviceConfig: ServiceConfig, virgilServiceConfig: VSSServiceConfig, deviceManager: VSSDeviceManagerProtocol, numberOfActiveOneTimeCards: Int, daysLongTermCardLives: Int, sessionTtl: TimeInterval) {
        self.myCardId = myCardId
        self.myPrivateKey = myPrivateKey
        self.crypto = crypto
        self.keyStorage = keyStorage
        self.serviceConfig = serviceConfig
        self.virgilServiceConfig = virgilServiceConfig
        self.deviceManager = deviceManager
        self.numberOfActiveOneTimeCards = numberOfActiveOneTimeCards
        self.daysLongTermCardLives = daysLongTermCardLives
        self.sessionTtl = sessionTtl
    }
    
    convenience public init(myCardId: String, myPrivateKey: VSSPrivateKey, accessToken: String) {
        self.init(myCardId: myCardId, myPrivateKey: myPrivateKey, crypto: VSSCrypto(), keyStorage: VSSKeyStorage(), serviceConfig: ServiceConfig(token: accessToken), virgilServiceConfig: VSSServiceConfig(token: accessToken), deviceManager: VSSDeviceManager(), numberOfActiveOneTimeCards: 100, daysLongTermCardLives: 7, sessionTtl: 60*60*24*3)
    }
}
