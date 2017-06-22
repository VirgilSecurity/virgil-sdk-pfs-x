//
//  SecureChat.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/20/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

@objc(VSPSecureChat) public class SecureChat: NSObject {
    public static let ErrorDomain = "VSPSecureChatErrorDomain"
    
    public let preferences: SecureChatPreferences
    public let client: Client
    public let virgilClient: VSSClient
    
    fileprivate let keyHelper: SecureChatKeyHelper
    
    fileprivate var identityCard: VSSCard?
    
    public init(preferences: SecureChatPreferences) {
        self.preferences = preferences
        self.client = Client(serviceConfig: self.preferences.serviceConfig)
        self.virgilClient = VSSClient(serviceConfig: self.preferences.virgilServiceConfig)
        
        self.keyHelper = SecureChatKeyHelper(crypto: self.preferences.crypto, keyStorage: self.preferences.keyStorage)
        
        super.init()
    }
}

// MARK: Talk init
extension SecureChat {
    private func initTalk(withCardsSet cardsSet: RecipientCardsSet, completion: @escaping (SecureTalk?, Error?)->()) throws {
        // FIXME: Check for existing session
        // FIXME: Add otc key on new session
        
        guard let identityCard = self.identityCard else {
            completion(nil, NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Identity card missing. Probably, SecureChat was not initialized."]))
            return
        }
        
        guard let publicKey = self.preferences.crypto.importPublicKey(from: identityCard.publicKeyData) else {
            completion(nil, NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error importing public key from identity card."]))
            return
        }
        
        let longTermPublicKeyData = cardsSet.longTermCard.publicKeyData
        let oneTimePublicKeyData = cardsSet.oneTimeCard.publicKeyData
        guard let oneTimePublicKey = self.preferences.crypto.importPublicKey(from: oneTimePublicKeyData),
            let longTermPublicKey = self.preferences.crypto.importPublicKey(from: longTermPublicKeyData) else {
                completion(nil, NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error importing eph public keys from cards."]))
                return
        }
        
        let recipientCardId = cardsSet.identityCard.identifier
        
        let ephKeyPair = self.preferences.crypto.generateKeyPair()
        let ephPrivateKey = ephKeyPair.privateKey
        
        let ephKeyName = try self.keyHelper.saveEphPrivateKey(ephPrivateKey, keyName: recipientCardId)
        
        let sessionState = SessionState(creationDate: Date(), ephKeyName: ephKeyName)
        try self.saveSessionState(sessionState, forRecipientCardId: recipientCardId)
        
        let secureTalk = SecureTalk(crypto: self.preferences.crypto, myPrivateKey: self.preferences.myPrivateKey, ephPrivateKey: ephPrivateKey, recipientPublicKey: publicKey, recipientLongTermKey: longTermPublicKey, recipientOneTimeKey: oneTimePublicKey)
        
        completion(secureTalk, nil)
    }
    
    public func initTalk(withRecipientWithIdentity identity: String, completion: @escaping (SecureTalk?, Error?)->()) {
        self.client.getRecipientCardsSet(forIdentities: [identity]) { cardsSets, error in
            guard error == nil else {
                completion(nil, NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error obtaining recipient cards set."]))
                return
            }
            
            guard let cardsSets = cardsSets, cardsSets.count > 0 else {
                completion(nil, NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error obtaining recipient cards set. Empty set."]))
                return
            }
            
            // FIXME: Multiple sessions?
            let cardsSet = cardsSets[0]
            
            do {
                try self.initTalk(withCardsSet: cardsSet) { secureTalk, error in
                    completion(secureTalk, error)
                }
            }
            catch {
                // FIXME
            }
        }
    }
}

// MARK: Session persistance
extension SecureChat {
    static private let DefaultsSuiteName = "VIRGIL.DEFAULTS"
    
    fileprivate func saveSessionState(_ sessionState: SessionState, forRecipientCardId cardId: String) throws {
        guard let userDefaults = UserDefaults(suiteName: SecureChat.DefaultsSuiteName) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while creating UserDefaults."])
        }
        
        userDefaults.set(sessionState, forKey: cardId)
    }
    
    fileprivate func getSessionState(forRecipientCardId cardId: String) throws -> SessionState? {
        guard let userDefaults = UserDefaults(suiteName: SecureChat.DefaultsSuiteName) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while creating UserDefaults."])
        }
        
        return userDefaults.value(forKey: cardId) as? SessionState
    }
}

// MARK: Initialization
extension SecureChat {
    // Workaround for Swift bug SR-2444
    public typealias CompletionHandler = (Error?) -> ()
    
    // FIXME: Check status of old keys and remove unneeded keys
    public func initialize(completion: CompletionHandler? = nil) {
        let errorCallback = { (error: Error?) in
            completion?(error)
        }
        
        var identityCard: VSSCard?
        var numberOfMissingCards: Int?
        
        var numberOfCompletedOperations = 0
        let numberOfOperations = 2
        let operationCompletedCallback = {
            numberOfCompletedOperations += 1
            
            if numberOfOperations == numberOfCompletedOperations {
                guard let identityCard = identityCard,
                    let numberOfMissingCards = numberOfMissingCards else {
                        errorCallback(NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "One or more initialization operations failed."]))
                        return
                }

                self.identityCard = identityCard
                if numberOfMissingCards > 0 {
                    //FIXME: Add longtermcard management
                    do {
                        try self.addCards(forIdentityCard: identityCard, includeLtcCard: true, numberOfOtcCards: numberOfMissingCards) { error in
                            guard error == nil else {
                                errorCallback(error!)
                                return
                            }
                            
                            completion?(nil)
                        }
                    }
                    catch {
                        errorCallback(error)
                    }
                }
                else {
                    completion?(nil)
                }
            }
        }
        
        // Get identity card
        self.virgilClient.getCard(withId: self.preferences.myCardId) { card, error in
            guard error == nil else {
                errorCallback(error)
                return
            }
            
            guard let card = card else {
                // FIXME
                errorCallback(nil)
                return
            }
            
            identityCard = card
            operationCompletedCallback()
        }
        
        // Check ephemeral cards status
        self.client.getCardsStatus(forUserWithCardId: self.preferences.myCardId) { status, error in
            guard error == nil else {
                errorCallback(error)
                return
            }
            
            guard let status = status else {
                // FIXME
                errorCallback(nil)
                return
            }
            
            // Not enough cards, add more
            numberOfMissingCards = max(self.preferences.numberOfActiveOneTimeCards - status.active, 0)
            operationCompletedCallback()
        }
    }
}

// MARK: Adding cards
extension SecureChat {
    private func generateRequest(forIdentityCard identityCard: VSSCard, keyPair: VSSKeyPair, isLtc: Bool) throws -> (CreateEphemeralCardRequest, String) {
        let identity = identityCard.identity
        let identityType = identityCard.identityType
        let device = self.preferences.deviceManager.getDeviceModel()
        let deviceName = self.preferences.deviceManager.getDeviceName()
        
        let publicKeyData = self.preferences.crypto.export(keyPair.publicKey)
        let request = CreateEphemeralCardRequest(identity: identity, identityType: identityType, publicKeyData: publicKeyData, data: nil, device: device, deviceName: deviceName)
        
        let requestSigner = VSSRequestSigner(crypto: self.preferences.crypto)
        let cardId = requestSigner.getCardId(forRequest: request)
        try requestSigner.authoritySign(request, forAppId: identityCard.identifier, with: self.preferences.myPrivateKey)
        
        return (request, cardId)
    }
    
    fileprivate func addCards(forIdentityCard identityCard: VSSCard, includeLtcCard: Bool, numberOfOtcCards: Int, completion: @escaping (Error?)->()) throws {
        var otcKeys: [SecureChatKeyHelper.KeyEntry] = []
        otcKeys.reserveCapacity(numberOfOtcCards)
        
        var otcCardsRequests: [CreateEphemeralCardRequest] = []
        otcCardsRequests.reserveCapacity(numberOfOtcCards)
        for _ in 0..<numberOfOtcCards {
            let keyPair = self.preferences.crypto.generateKeyPair()
            
            let (request, cardId) = try self.generateRequest(forIdentityCard: identityCard, keyPair: keyPair, isLtc: false)
            otcCardsRequests.append(request)
            
            let keyEntry = SecureChatKeyHelper.KeyEntry(privateKey: keyPair.privateKey, keyName: cardId)
            otcKeys.append(keyEntry)
        }
        
        let ltcKey: SecureChatKeyHelper.KeyEntry?
        let ltcCardRequest: CreateEphemeralCardRequest?
        if includeLtcCard {
            let keyPair = self.preferences.crypto.generateKeyPair()
            let (request, cardId) = try self.generateRequest(forIdentityCard: identityCard, keyPair: keyPair, isLtc: true)
            ltcCardRequest = request
            
            ltcKey = SecureChatKeyHelper.KeyEntry(privateKey: keyPair.privateKey, keyName: cardId)
        }
        else {
            ltcKey = nil
            ltcCardRequest = nil
        }
        
        try self.keyHelper.saveKeys(keys: otcKeys, ltKey: ltcKey)
        
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
                    callback(NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [ NSLocalizedDescriptionKey: "Error while bootstraping ephemeral cards"]))
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
                    callback(NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [ NSLocalizedDescriptionKey: "Error while adding one-time ephemeral cards"]))
                    return
                }
                
                callback(nil)
            }
        }
    }
}
