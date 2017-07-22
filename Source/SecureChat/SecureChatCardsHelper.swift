//
//  SecureChatCardsHelper.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

class SecureChatCardsHelper {
    private let crypto: VSSCryptoProtocol
    private let myPrivateKey: VSSPrivateKey
    private let client: Client
    private let deviceManager: VSSDeviceManagerProtocol
    private let keyHelper: SecureChatKeyHelper
    
    init(crypto: VSSCryptoProtocol, myPrivateKey: VSSPrivateKey, client: Client, deviceManager: VSSDeviceManagerProtocol, keyHelper: SecureChatKeyHelper) {
        self.crypto = crypto
        self.myPrivateKey = myPrivateKey
        self.client = client
        self.deviceManager = deviceManager
        self.keyHelper = keyHelper
    }
    
    private func generateRequest(forIdentityCard identityCard: VSSCard, keyPair: VSSKeyPair, isLtc: Bool) throws -> (CreateEphemeralCardRequest, String) {
        let identity = identityCard.identity
        let identityType = identityCard.identityType
        let device = self.deviceManager.getDeviceModel()
        let deviceName = self.deviceManager.getDeviceName()
        
        let publicKeyData = self.crypto.export(keyPair.publicKey)
        let request = CreateEphemeralCardRequest(identity: identity, identityType: identityType, publicKeyData: publicKeyData, data: nil, device: device, deviceName: deviceName)
        
        let requestSigner = VSSRequestSigner(crypto: self.crypto)
        let cardId = requestSigner.getCardId(forRequest: request)
        try requestSigner.authoritySign(request, forAppId: identityCard.identifier, with: self.myPrivateKey)
        
        return (request, cardId)
    }
    
    func addCards(forIdentityCard identityCard: VSSCard, includeLtcCard: Bool, numberOfOtcCards: Int, completion: @escaping (Error?)->()) throws {
        var otcKeys: [SecureChatKeyHelper.KeyEntry] = []
        otcKeys.reserveCapacity(numberOfOtcCards)
        
        var otcCardsRequests: [CreateEphemeralCardRequest] = []
        otcCardsRequests.reserveCapacity(numberOfOtcCards)
        for _ in 0..<numberOfOtcCards {
            let keyPair = self.crypto.generateKeyPair()
            
            let (request, cardId) = try self.generateRequest(forIdentityCard: identityCard, keyPair: keyPair, isLtc: false)
            otcCardsRequests.append(request)
            
            let keyEntry = SecureChatKeyHelper.KeyEntry(privateKey: keyPair.privateKey, keyName: cardId)
            otcKeys.append(keyEntry)
        }
        
        let ltcKey: SecureChatKeyHelper.KeyEntry?
        let ltcCardRequest: CreateEphemeralCardRequest?
        if includeLtcCard {
            let keyPair = self.crypto.generateKeyPair()
            let (request, cardId) = try self.generateRequest(forIdentityCard: identityCard, keyPair: keyPair, isLtc: true)
            ltcCardRequest = request
            
            ltcKey = SecureChatKeyHelper.KeyEntry(privateKey: keyPair.privateKey, keyName: cardId)
        }
        else {
            ltcKey = nil
            ltcCardRequest = nil
        }
        
        try self.keyHelper.persistKeys(keys: otcKeys, ltKey: ltcKey)
        
        let callback = { (error: Error?) in
            completion(error)
        }
        
        if let ltcCardRequest = ltcCardRequest {
            self.client.bootstrapCardsSet(forUserWithCardId: identityCard.identifier, longTermCardRequest: ltcCardRequest, oneTimeCardsRequests: otcCardsRequests) { ltcCard, otcCards, error in
                guard error == nil else {
                    callback(error!)
                    return
                }
                
                guard ltcCard != nil, otcCards != nil else {
                    callback(NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.bootstrapingEphemeralCards.rawValue, userInfo: [ NSLocalizedDescriptionKey: "Error while bootstraping ephemeral cards"]))
                    return
                }
                
                callback(nil)
            }
        }
        else if otcCardsRequests.count > 0 {
            self.client.createOneTimeCards(forUserWithCardId: identityCard.identifier, oneTimeCardsRequests: otcCardsRequests) { otcCards, error in
                guard error == nil else {
                    callback(error!)
                    return
                }
                
                guard otcCards != nil else {
                    callback(NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.addingOneTimeEphemeralCards.rawValue, userInfo: [ NSLocalizedDescriptionKey: "Error while adding one-time ephemeral cards"]))
                    return
                }
                
                callback(nil)
            }
        }
    }
}
