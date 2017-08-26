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
    public var keyStorage: KeyStorage
    public var insensitiveDataStorage: InsensitiveDataStorage
    public var deviceManager: VSSDeviceManagerProtocol
    public var serviceConfig: ServiceConfig
    public var longTermKeysTtl: TimeInterval
    public var sessionTtl: TimeInterval
    public var oneTimeCardExhaustTtl: TimeInterval
    
    public init(crypto: VSSCryptoProtocol, privateKey: VSSPrivateKey, identityCard: VSSCard, keyStorage: KeyStorage? = nil, insensitiveDataStorage: InsensitiveDataStorage? = nil, deviceManager: VSSDeviceManagerProtocol? = nil, serviceConfig: ServiceConfig, longTermKeysTtl: TimeInterval? = nil, sessionTtl: TimeInterval? = nil, oneTimeCardExhaustTtl: TimeInterval? = nil) throws {
        self.crypto = crypto
        self.privateKey = privateKey
        self.identityCard = identityCard
        self.keyStorage = keyStorage ?? KeychainKeyStorage(virgilKeyStorage: VSSKeyStorage())
        self.insensitiveDataStorage = try insensitiveDataStorage ?? UserDefaultsDataStorage.makeStorage(forIdentifier: identityCard.identifier)
        self.deviceManager = deviceManager ?? VSSDeviceManager()
        self.serviceConfig = serviceConfig
        self.longTermKeysTtl = longTermKeysTtl ?? 60*60*24*7
        self.sessionTtl = sessionTtl ?? 60*60*24*3
        self.oneTimeCardExhaustTtl = oneTimeCardExhaustTtl ?? 60*60*24
    }
    
    convenience public init(crypto: VSSCryptoProtocol, identityCard: VSSCard, privateKey: VSSPrivateKey, accessToken: String) throws {
        try self.init(crypto: crypto, privateKey: privateKey, identityCard: identityCard, keyStorage: nil, deviceManager: nil, serviceConfig: ServiceConfig(token: accessToken))
    }
}
