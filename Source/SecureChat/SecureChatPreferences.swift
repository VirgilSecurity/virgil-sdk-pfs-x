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
    public let crypto: VSSCryptoProtocol
    public let privateKey: VSSPrivateKey
    public let identityCard: VSSCard
    public let keyStorage: VSSKeyStorageProtocol
    public let deviceManager: VSSDeviceManagerProtocol
    public let serviceConfig: ServiceConfig
    public let longTermKeysTtl: TimeInterval
    public let sessionTtl: TimeInterval
    
    public class func secureChatPreferences(withCrypto crypto: VSSCryptoProtocol, privateKey: VSSPrivateKey, identityCard: VSSCard, keyStorage: VSSKeyStorageProtocol? = nil, deviceManager: VSSDeviceManagerProtocol? = nil, serviceConfig: ServiceConfig, longTermKeysTtl: NSNumber? = nil, sessionTtl: NSNumber? = nil) -> SecureChatPreferences {
        return SecureChatPreferences(crypto: crypto, privateKey: privateKey, identityCard: identityCard, keyStorage: keyStorage, deviceManager: deviceManager, serviceConfig: serviceConfig, longTermKeysTtl: longTermKeysTtl?.doubleValue, sessionTtl: sessionTtl?.doubleValue)
    }
    
    public init(crypto: VSSCryptoProtocol, privateKey: VSSPrivateKey, identityCard: VSSCard, keyStorage: VSSKeyStorageProtocol? = nil, deviceManager: VSSDeviceManagerProtocol? = nil, serviceConfig: ServiceConfig, longTermKeysTtl: TimeInterval? = nil, sessionTtl: TimeInterval? = nil) {
        self.crypto = crypto
        self.privateKey = privateKey
        self.identityCard = identityCard
        self.keyStorage = keyStorage ?? VSSKeyStorage()
        self.deviceManager = deviceManager ?? VSSDeviceManager()
        self.serviceConfig = serviceConfig
        self.longTermKeysTtl = longTermKeysTtl ?? 60*60*24*7
        self.sessionTtl = sessionTtl ?? 60*60*24*3
    }
    
    convenience public init(crypto: VSSCryptoProtocol, identityCard: VSSCard, privateKey: VSSPrivateKey, accessToken: String) {
        self.init(crypto: crypto, privateKey: privateKey, identityCard: identityCard, keyStorage: nil, deviceManager: nil, serviceConfig: ServiceConfig(token: accessToken), longTermKeysTtl: nil, sessionTtl: nil)
    }
}
