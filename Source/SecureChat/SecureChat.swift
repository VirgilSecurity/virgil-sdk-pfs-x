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
    
    fileprivate var identityCard: VSSCard?
    
    public init(preferences: SecureChatPreferences) {
        self.preferences = preferences
        self.client = Client(serviceConfig: self.preferences.serviceConfig)
        self.virgilClient = VSSClient(serviceConfig: self.preferences.virgilServiceConfig)
    }

    public func initTalk(withCardId cardId: String, completion: @escaping (SecureTalk?, Error?)->()) {
        guard let identityCard = self.identityCard else {
            completion(nil, NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Identity card missing. Probably, SecureChat was not initialized."]))
            return
        }
        

        guard let publicKey = self.preferences.crypto.importPublicKey(from: identityCard.publicKeyData) else {
            completion(nil, NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error importing public key from identity card."]))
            return
        }

        // FIXME
        let secureTalk = SecureTalk(crypto: self.preferences.crypto, myPrivateKey: self.preferences.myPrivateKey, ephPrivateKey: self.preferences.crypto.generateKeyPair().privateKey, recipientPublicKey: publicKey, recipientLongTermKey: self.preferences.crypto.generateKeyPair().publicKey, recipientOneTimeKey: self.preferences.crypto.generateKeyPair().publicKey)
        
        completion(secureTalk, nil)
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
    private func generateRequest(forIdentityCard identityCard: VSSCard, privateKey: VSSPrivateKey, isLtc: Bool) throws -> CreateEphemeralCardRequest {
        let identity = identityCard.identity
        let identityType = identityCard.identityType
        let device = self.preferences.deviceManager.getDeviceModel()
        let deviceName = self.preferences.deviceManager.getDeviceName()
        
        // FIXME: SAVE KEY
        let keyPair = self.preferences.crypto.generateKeyPair()
        let publicKeyData = self.preferences.crypto.export(keyPair.publicKey)
        let request = CreateEphemeralCardRequest(identity: identity, identityType: identityType, publicKeyData: publicKeyData, data: nil, device: device, deviceName: deviceName)
        
        let requestSigner = VSSRequestSigner(crypto: self.preferences.crypto)
        try requestSigner.selfSign(request, with: keyPair.privateKey)
        try requestSigner.authoritySign(request, forAppId: identityCard.identifier, with: self.preferences.myPrivateKey)
        
        return request
    }
    
    fileprivate func addCards(forIdentityCard identityCard: VSSCard, includeLtcCard: Bool, numberOfOtcCards: Int, completion: @escaping (Error?)->()) throws {
        let keys = try self.generateAndSaveKeys(numberOfKeys: numberOfOtcCards + (includeLtcCard ? 1 : 0))
        
        var otcCardsRequests: [CreateEphemeralCardRequest] = []
        otcCardsRequests.reserveCapacity(numberOfOtcCards)
        for i in 0..<numberOfOtcCards {
            let request = try self.generateRequest(forIdentityCard: identityCard, privateKey: keys[i].privateKey, isLtc: false)
            otcCardsRequests.append(request)
        }
        
        var ltcCardRequest: CreateEphemeralCardRequest?
        if includeLtcCard {
            let request = try self.generateRequest(forIdentityCard: identityCard, privateKey: keys.last!.privateKey, isLtc: false)
            ltcCardRequest = request
        }
        
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

// MARK: Keys
extension SecureChat {
    static fileprivate let ServiceKeyName = "VIRGIL.SERVICE.INFO"
    static private let DateFormatRFC3339 = "yyyy-MM-dd'T'HH:mm:ssZZZZZ"
    static private let KeyNameFormat = "%@.%@.%@.%@"
    
    private func savePrivateKeys(_ keys: [VSSPrivateKey]) throws -> [String] {
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = SecureChat.DateFormatRFC3339
        let dateStr = dateFormatter.string(from: Date())
        
        var keyNames: [String] = []
        keyNames.reserveCapacity(keys.count)
        
        for privateKey in keys {
            let privateKeyData = self.preferences.crypto.export(privateKey, withPassword: nil)
            
            let keyName = String(format: SecureChat.KeyNameFormat, "VIRGIL", "OTKEY", dateStr, UUID().uuidString)
            keyNames.append(keyName)
            let keyEntry = VSSKeyEntry(name: keyName, value: privateKeyData)
            
            try self.preferences.keyStorage.store(keyEntry)
        }
        
        return keyNames
    }
    
    fileprivate func generateAndSaveKeys(numberOfKeys: Int) throws -> [VSSKeyPair] {
        let serviceInfo = try self.getServiceInfoEntry()
        
        var keyPairs: [VSSKeyPair] = []
        for _ in 0..<numberOfKeys {
            keyPairs.append(self.preferences.crypto.generateKeyPair())
        }
        
        let names = try self.savePrivateKeys(keyPairs.map({ return $0.privateKey }))
        
        let newServiceInfo = ServiceInfoEntry(otcKeysNames: serviceInfo.otcKeysNames + names)
        
        try self.updateServiceInfoEntry(newEntry: newServiceInfo)
        
        return keyPairs
    }
    
    private func updateServiceInfoEntry(newEntry: ServiceInfoEntry) throws {
        // FIXME: Replace with update
        try self.preferences.keyStorage.deleteKeyEntry(withName: SecureChat.ServiceKeyName)
        
        let data = NSKeyedArchiver.archivedData(withRootObject: newEntry)
        let keyEntry = VSSKeyEntry(name: SecureChat.ServiceKeyName, value: data)
        
        try self.preferences.keyStorage.store(keyEntry)
    }
    
    private func getServiceInfoEntry() throws -> ServiceInfoEntry {
        guard let keyEntry = try? self.preferences.keyStorage.loadKeyEntry(withName: SecureChat.ServiceKeyName) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error getting service info key."])
        }
        
        guard let serviceInfoEntry = NSKeyedUnarchiver.unarchiveObject(with: keyEntry.value) as? ServiceInfoEntry else {
            throw NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error unarchiving service info key."])
        }
        
        return serviceInfoEntry
    }
}
