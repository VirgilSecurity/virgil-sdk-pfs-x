//
//  SecureChatPreferences.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/20/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

/// Class used to setup SecureChat
@objc(VSPSecureChatPreferences) public class SecureChatPreferences: NSObject {
    /// Crypto implementation (e.g. VSSCrypto from VirgilSDK)
    public let crypto: VSSCryptoProtocol
    
    /// User's private key that corresponds to his identity card on Virgil Cards Service
    public let identityPrivateKey: VSSPrivateKey
    
    /// User's identity card
    public let identityCard: VSSCard
    
    /// KeyStorage implementation used to store private/symmetric keys needed for PFS (default is KeychainKeyStorage)
    public var keyStorage: KeyStorage
    
    /// InsensitiveDataStorage implementation used to store insensitive data (sessions info, ltc/otc/sessions lifetime info) (default is UserDefaultsDataStorage)
    public var insensitiveDataStorage: InsensitiveDataStorage
    
    /// PFS service url
    public var pfsUrl: URL?
    
    /// Access token for Virgil Services. Can be obtained here https://developer.virgilsecurity.com/account/dashboard/
    public var accessToken: String
    
    /// Long-term keys time-to-live in seconds (time during which long-term key is considered relevant and won't be replaced)
    public var longTermKeysTtl: TimeInterval
    
    /// Expired long-term keys time-to-live in seconds (time during which expired long-term key is not removed)
    public var expiredLongTermKeysTtl: TimeInterval
    
    /// Session time-to-live in seconds (time during which session is considered relevant and won't be replaced)
    public var sessionTtl: TimeInterval
    
    /// Expired session time-to-live in seconds (time during which expired session key is not removed)
    public var expiredSessionTtl: TimeInterval
    
    /// Exhausted one-time keys time-to-live in seconds (time during which one-time is not removed after sdk determined that it was exhausted)
    public var exhaustedOneTimeKeysTtl: TimeInterval
    
    var client: Client { return Client(serviceConfig: ServiceConfig(token: self.accessToken, ephemeralServiceURL: self.pfsUrl)) }
    
    /// Initializer
    ///
    /// - Parameters:
    ///   - crypto: Crypto implementation (e.g. VSSCrypto from VirgilSDK)
    ///   - identityPrivateKey: User's private key that corresponds to his identity card on Virgil Cards Service
    ///   - identityCard: User's identity card. WARNING: Identity Card should be validated before getting here!
    ///   - keyStorage: KeyStorage implementation used to store private/symmetric keys needed for PFS (default is KeychainKeyStorage)
    ///   - insensitiveDataStorage: InsensitiveDataStorage implementation used to store insensitive data (sessions info, ltc/otc/sessions lifetime info) (default is UserDefaultsDataStorage)
    ///   - pfsUrl: PFS service url
    ///   - accessToken: Access token for Virgil Services. Can be obtained here https://developer.virgilsecurity.com/account/dashboard/
    ///   - longTermKeysTtl: Long-term keys time-to-live in seconds (time during which long-term key is considered relevant and won't be replaced)
    ///   - expiredLongTermKeysTtl: Expired long-term keys time-to-live in seconds (time during which expired long-term key is not removed)
    ///   - sessionTtl: Session time-to-live in seconds (time during which session is considered relevant and won't be replaced)
    ///   - expiredSessionTtl: Expired session time-to-live in seconds (time during which expired session key is not removed)
    ///   - exhaustedOneTimeKeysTtl: Exhausted one-time keys time-to-live in seconds (time during which one-time is not removed after sdk determined that it was exhausted)
    /// - Throws: Throws error when using default UserDefaultsDataStorage implementation of InsensitiveDataStorage and UserDefaults suite creation has failed
    public init(crypto: VSSCryptoProtocol, identityPrivateKey: VSSPrivateKey, identityCard: VSSCard, keyStorage: KeyStorage? = nil, insensitiveDataStorage: InsensitiveDataStorage? = nil, pfsUrl: URL?, accessToken: String, longTermKeysTtl: TimeInterval? = nil, expiredLongTermKeysTtl: TimeInterval? = nil, sessionTtl: TimeInterval? = nil, expiredSessionTtl: TimeInterval? = nil, exhaustedOneTimeKeysTtl: TimeInterval? = nil) throws {
        self.crypto = crypto
        self.identityPrivateKey = identityPrivateKey
        self.identityCard = identityCard
        self.keyStorage = keyStorage ?? KeychainKeyStorage(virgilKeyStorage: VSSKeyStorage())
        self.insensitiveDataStorage = try insensitiveDataStorage ?? UserDefaultsDataStorage.makeStorage(forIdentifier: identityCard.identifier)
        self.pfsUrl = pfsUrl
        self.accessToken = accessToken
        self.longTermKeysTtl = longTermKeysTtl ?? 60*60*24*7
        self.expiredLongTermKeysTtl = expiredLongTermKeysTtl ?? 60*60*24
        self.sessionTtl = sessionTtl ?? 60*60*24*3
        self.expiredSessionTtl = expiredSessionTtl ?? 60*60*24
        self.exhaustedOneTimeKeysTtl = exhaustedOneTimeKeysTtl ?? 60*60*24
    }
    
    /// Convenience initializer
    ///
    /// - Parameters:
    ///   - crypto: Crypto implementation (e.g. VSSCrypto from VirgilSDK)
    ///   - identityPrivateKey: User's private key that corresponds to his identity card on Virgil Cards Service
    ///   - identityCard: User's identity card. WARNING: Identity Card should be validated before getting here!
    ///   - accessToken: Access token for Virgil Services. Can be obtained here https://developer.virgilsecurity.com/account/dashboard/
    /// - Throws: see designated initializer
    convenience public init(crypto: VSSCryptoProtocol, identityPrivateKey: VSSPrivateKey, identityCard: VSSCard, accessToken: String) throws {
        try self.init(crypto: crypto, identityPrivateKey: identityPrivateKey, identityCard: identityCard, accessToken: accessToken)
    }
}
