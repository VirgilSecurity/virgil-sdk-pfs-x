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
    private let identityPrivateKey: VSSPrivateKey
    private let identityCardId: String
    private let client: Client
    private let deviceManager: VSSDeviceManagerProtocol
    private let keyHelper: SecureChatKeyHelper
    
    init(crypto: VSSCryptoProtocol, identityPrivateKey: VSSPrivateKey, identityCardId: String, client: Client, deviceManager: VSSDeviceManagerProtocol, keyHelper: SecureChatKeyHelper) {
        self.crypto = crypto
        self.identityPrivateKey = identityPrivateKey
        self.identityCardId = identityCardId
        self.client = client
        self.deviceManager = deviceManager
        self.keyHelper = keyHelper
    }
    
    private func generateRequest(withKeyPair keyPair: VSSKeyPair, isLtc: Bool) throws -> (CreateEphemeralCardRequest, String) {
        let identity = self.identityCardId
        let identityType = "identity_card_id"
        let device = self.deviceManager.getDeviceModel()
        let deviceName = self.deviceManager.getDeviceName()
        
        let publicKeyData = self.crypto.export(keyPair.publicKey)
        let request = CreateEphemeralCardRequest(identity: identity, identityType: identityType, publicKeyData: publicKeyData, data: nil, device: device, deviceName: deviceName)
        
        let requestSigner = VSSRequestSigner(crypto: self.crypto)
        let cardId = requestSigner.getCardId(forRequest: request)
        try requestSigner.authoritySign(request, forAppId: self.identityCardId, with: self.identityPrivateKey)
        
        return (request, cardId)
    }
    
    func addCards(includeLtcCard: Bool, numberOfOtcCards: Int, completion: @escaping (Error?)->()) throws {
        Log.debug("Adding \(numberOfOtcCards) cards for: \(self.identityCardId), include lt: \(includeLtcCard)")
        
        var otcKeys: [SecureChatKeyHelper.HelperKeyEntry] = []
        otcKeys.reserveCapacity(numberOfOtcCards)
        
        var otcCardsRequests: [CreateEphemeralCardRequest] = []
        otcCardsRequests.reserveCapacity(numberOfOtcCards)
        for _ in 0..<numberOfOtcCards {
            let keyPair = self.crypto.generateKeyPair()
            
            let (request, cardId) = try self.generateRequest(withKeyPair: keyPair, isLtc: false)
            otcCardsRequests.append(request)
            
            let keyEntry = SecureChatKeyHelper.HelperKeyEntry(privateKey: keyPair.privateKey, keyName: cardId)
            otcKeys.append(keyEntry)
        }
        
        let ltcKey: SecureChatKeyHelper.HelperKeyEntry?
        let ltcCardRequest: CreateEphemeralCardRequest?
        if includeLtcCard {
            let keyPair = self.crypto.generateKeyPair()
            let (request, cardId) = try self.generateRequest(withKeyPair: keyPair, isLtc: true)
            ltcCardRequest = request
            
            ltcKey = SecureChatKeyHelper.HelperKeyEntry(privateKey: keyPair.privateKey, keyName: cardId)
        }
        else {
            ltcKey = nil
            ltcCardRequest = nil
        }
        
        try self.keyHelper.persistKeys(keys: otcKeys, ltKey: ltcKey)
        
        let callback = { (error: Error?) in
            if let error = error {
                Log.debug("Error adding \(numberOfOtcCards) cards for: \(self.identityCardId), include lt: \(includeLtcCard). Error: \(error.localizedDescription)")
            }
            else {
                Log.debug("Successfully added \(numberOfOtcCards) cards for: \(self.identityCardId), include lt: \(includeLtcCard)")
            }
            
            completion(error)
        }
        
        if let ltcCardRequest = ltcCardRequest {
            self.client.bootstrapCardsSet(forUserWithCardId: self.identityCardId, longTermCardRequest: ltcCardRequest, oneTimeCardsRequests: otcCardsRequests) { ltcCard, otcCards, error in
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
            self.client.createOneTimeCards(forUserWithCardId: self.identityCardId, oneTimeCardsRequests: otcCardsRequests) { otcCards, error in
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
