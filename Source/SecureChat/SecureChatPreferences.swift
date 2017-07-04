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
    public let myIdentityCard: VSSCard
    public let myPrivateKey: VSSPrivateKey
    public let crypto: VSSCryptoProtocol
    public let keyStorage: VSSKeyStorageProtocol
    public let serviceConfig: ServiceConfig
    public let cardValidator: VSSCardValidator
    public let deviceManager: VSSDeviceManagerProtocol
    public let numberOfActiveOneTimeCards: Int
    public let longTermKeysTtl: TimeInterval
    public let sessionTtl: TimeInterval
    
    
    public init(myIdentityCard: VSSCard, myPrivateKey: VSSPrivateKey, crypto: VSSCryptoProtocol, keyStorage: VSSKeyStorageProtocol, serviceConfig: ServiceConfig, cardValidator: VSSCardValidator, deviceManager: VSSDeviceManagerProtocol, numberOfActiveOneTimeCards: Int, longTermKeysTtl: TimeInterval, sessionTtl: TimeInterval) {
        self.myIdentityCard = myIdentityCard
        self.myPrivateKey = myPrivateKey
        self.crypto = crypto
        self.keyStorage = keyStorage
        self.serviceConfig = serviceConfig
        self.cardValidator = cardValidator
        self.deviceManager = deviceManager
        self.numberOfActiveOneTimeCards = numberOfActiveOneTimeCards
        self.longTermKeysTtl = longTermKeysTtl
        self.sessionTtl = sessionTtl
    }
    
    convenience public init(myIdentityCard: VSSCard, myPrivateKey: VSSPrivateKey, accessToken: String, cardValidator: VSSCardValidator) {
        self.init(myIdentityCard: myIdentityCard, myPrivateKey: myPrivateKey, crypto: VSSCrypto(), keyStorage: VSSKeyStorage(), serviceConfig: ServiceConfig(token: accessToken), cardValidator: cardValidator, deviceManager: VSSDeviceManager(), numberOfActiveOneTimeCards: 100, longTermKeysTtl: 60*60*24*7, sessionTtl: 60*60*24*3)
    }
}
