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
    public let keyStorage: KeyStorage
    public let storageFactory: InsensitiveDataStorageFactory
    public let deviceManager: VSSDeviceManagerProtocol
    public let serviceConfig: ServiceConfig
    public let longTermKeysTtl: TimeInterval
    public let sessionTtl: TimeInterval
    public let onetimeCardExhaustLifetime: TimeInterval
    
    public class func secureChatPreferences(withCrypto crypto: VSSCryptoProtocol, privateKey: VSSPrivateKey, identityCard: VSSCard, keyStorage: KeyStorage? = nil, deviceManager: VSSDeviceManagerProtocol? = nil, serviceConfig: ServiceConfig, longTermKeysTtl: NSNumber? = nil, sessionTtl: NSNumber? = nil, onetimeCardExhaustLifetime: NSNumber? = nil) -> SecureChatPreferences {
        return SecureChatPreferences(crypto: crypto, privateKey: privateKey, identityCard: identityCard, keyStorage: keyStorage, deviceManager: deviceManager, serviceConfig: serviceConfig, longTermKeysTtl: longTermKeysTtl?.doubleValue, sessionTtl: sessionTtl?.doubleValue, onetimeCardExhaustLifetime: onetimeCardExhaustLifetime?.doubleValue)
    }
    
    public init(crypto: VSSCryptoProtocol, privateKey: VSSPrivateKey, identityCard: VSSCard, keyStorage: KeyStorage? = nil, storageFactory: InsensitiveDataStorageFactory? = nil, deviceManager: VSSDeviceManagerProtocol? = nil, serviceConfig: ServiceConfig, longTermKeysTtl: TimeInterval? = nil, sessionTtl: TimeInterval? = nil, onetimeCardExhaustLifetime: TimeInterval? = nil) {
        self.crypto = crypto
        self.privateKey = privateKey
        self.identityCard = identityCard
        self.keyStorage = keyStorage ?? KeychainKeyStorage(virgilKeyStorage: VSSKeyStorage())
        self.storageFactory = storageFactory ?? UserDefaultsDataStorageFactory()
        self.deviceManager = deviceManager ?? VSSDeviceManager()
        self.serviceConfig = serviceConfig
        self.longTermKeysTtl = longTermKeysTtl ?? 60*60*24*7
        self.sessionTtl = sessionTtl ?? 60*60*24*3
        self.onetimeCardExhaustLifetime = onetimeCardExhaustLifetime ?? 60*60*24
    }
    
    convenience public init(crypto: VSSCryptoProtocol, identityCard: VSSCard, privateKey: VSSPrivateKey, accessToken: String) {
        self.init(crypto: crypto, privateKey: privateKey, identityCard: identityCard, keyStorage: nil, deviceManager: nil, serviceConfig: ServiceConfig(token: accessToken), longTermKeysTtl: nil, sessionTtl: nil)
    }
}
