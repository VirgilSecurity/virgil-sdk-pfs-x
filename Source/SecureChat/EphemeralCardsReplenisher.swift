//
//  EphemeralCardsReplenisher.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

class EphemeralCardsReplenisher {
    private let crypto: VSSCryptoProtocol
    private let identityPrivateKey: VSSPrivateKey
    private let identityCardId: String
    private let client: Client
    private let keyStorageManager: KeyStorageManager
    
    init(crypto: VSSCryptoProtocol, identityPrivateKey: VSSPrivateKey, identityCardId: String, client: Client, keyStorageManager: KeyStorageManager) {
        self.crypto = crypto
        self.identityPrivateKey = identityPrivateKey
        self.identityCardId = identityCardId
        self.client = client
        self.keyStorageManager = keyStorageManager
    }
    
    private func generateRequest(withKeyPair keyPair: VSSKeyPair, isLtc: Bool) throws -> (CreateEphemeralCardRequest, String) {
        let identity = self.identityCardId
        let identityType = "identity_card_id"
        
        let publicKeyData = self.crypto.export(keyPair.publicKey)
        let request = CreateEphemeralCardRequest(identity: identity, identityType: identityType, publicKeyData: publicKeyData, data: nil)
        
        let requestSigner = VSSRequestSigner(crypto: self.crypto)
        let cardId = requestSigner.getCardId(forRequest: request)
        try requestSigner.authoritySign(request, forAppId: self.identityCardId, with: self.identityPrivateKey)
        
        return (request, cardId)
    }
    
    func addCards(includeLtcCard: Bool, numberOfOtcCards: Int, completion: @escaping (Error?)->()) throws {
        Log.debug("Adding \(numberOfOtcCards) cards for: \(self.identityCardId), include lt: \(includeLtcCard)")
        
        var otcKeys: [KeyStorageManager.HelperKeyEntry] = []
        otcKeys.reserveCapacity(numberOfOtcCards)
        
        var otcCardsRequests: [CreateEphemeralCardRequest] = []
        otcCardsRequests.reserveCapacity(numberOfOtcCards)
        
        let keyPairs = self.crypto.generateMultipleKeyPairs(UInt(numberOfOtcCards))
        
        for keyPair in keyPairs {
            let (request, cardId) = try self.generateRequest(withKeyPair: keyPair, isLtc: false)
            otcCardsRequests.append(request)
            
            let keyEntry = KeyStorageManager.HelperKeyEntry(privateKey: keyPair.privateKey, name: cardId)
            otcKeys.append(keyEntry)
        }
        
        let ltcKey: KeyStorageManager.HelperKeyEntry?
        let ltcCardRequest: CreateEphemeralCardRequest?
        if includeLtcCard {
            let keyPair = self.crypto.generateKeyPair()
            let (request, cardId) = try self.generateRequest(withKeyPair: keyPair, isLtc: true)
            ltcCardRequest = request
            
            ltcKey = KeyStorageManager.HelperKeyEntry(privateKey: keyPair.privateKey, name: cardId)
        }
        else {
            ltcKey = nil
            ltcCardRequest = nil
        }
        
        try self.keyStorageManager.saveKeys(otKeys: otcKeys, ltKey: ltcKey)
        
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
