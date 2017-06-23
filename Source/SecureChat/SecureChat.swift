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
    fileprivate let cardsHelper: SecureChatCardsHelper
    fileprivate let sessionHelper: SecureChatSessionHelper
    
    fileprivate var identityCard: VSSCard?
    
    public init(preferences: SecureChatPreferences) {
        self.preferences = preferences
        self.client = Client(serviceConfig: self.preferences.serviceConfig)
        self.virgilClient = VSSClient(serviceConfig: self.preferences.virgilServiceConfig)
        
        self.keyHelper = SecureChatKeyHelper(crypto: self.preferences.crypto, keyStorage: self.preferences.keyStorage, identityCardId: self.preferences.myCardId)
        self.cardsHelper = SecureChatCardsHelper(crypto: self.preferences.crypto, myPrivateKey: self.preferences.myPrivateKey, client: self.client, deviceManager: self.preferences.deviceManager, keyHelper: self.keyHelper)
        self.sessionHelper = SecureChatSessionHelper(cardId: self.preferences.myCardId)
        
        super.init()
    }
}

// MARK: Talk initiation
extension SecureChat {
    private func initiateTalk(withCardsSet cardsSet: RecipientCardsSet, completion: @escaping (SecureTalk?, Error?)->()) throws {
        // FIXME: Check for existing session
        guard let identityCard = self.identityCard else {
            completion(nil, NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Identity card missing. Probably, SecureChat was not initialized."]))
            return
        }
        
        let identityPublicKeyData = cardsSet.identityCard.publicKeyData
        let longTermPublicKeyData = cardsSet.longTermCard.publicKeyData
        let oneTimePublicKeyData = cardsSet.oneTimeCard.publicKeyData
        let recipientCardId = cardsSet.identityCard.identifier
        
        let ephKeyPair = self.preferences.crypto.generateKeyPair()
        let ephPrivateKey = ephKeyPair.privateKey
        
        let ephKeyName = try self.keyHelper.saveEphPrivateKey(ephPrivateKey, name: recipientCardId)
        
        // FIXME: Optional one time key?
        let sessionState = InitiatorSessionState(creationDate: Date(), ephKeyName: ephKeyName, recipientCardId: cardsSet.identityCard.identifier, recipientPublicKey: identityPublicKeyData, recipientLongTermCardId: cardsSet.longTermCard.identifier, recipientLongTermPublicKey: longTermPublicKeyData, recipientOneTimeCardId: cardsSet.oneTimeCard.identifier, recipientOneTimePublicKey: oneTimePublicKeyData)
        try self.sessionHelper.saveSessionState(sessionState, forRecipientCardId: recipientCardId, crypto: self.preferences.crypto)
        
        let validator = EphemeralCardValidator(crypto: self.preferences.crypto)
        
        // FIXME validate identity card
        
        try validator.addVerifier(withId: cardsSet.identityCard.identifier, publicKeyData: cardsSet.identityCard.publicKeyData)
        
        guard validator.validate(cardResponse: cardsSet.longTermCard.cardResponse) else {
            throw NSError(domain: SecureTalk.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Initiator LongTerm card validation failed."])
        }
        guard validator.validate(cardResponse: cardsSet.oneTimeCard.cardResponse) else {
            throw NSError(domain: SecureTalk.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Initiator OneTime card validation failed."])
        }
        
        let identityCardEntry = SecureTalk.CardEntry(identifier: cardsSet.identityCard.identifier, publicKeyData: identityPublicKeyData)
        let ltCardEntry = SecureTalk.CardEntry(identifier: cardsSet.longTermCard.identifier, publicKeyData: longTermPublicKeyData)
        let otCardEntry = SecureTalk.CardEntry(identifier: cardsSet.oneTimeCard.identifier, publicKeyData: oneTimePublicKeyData)
        
        let secureTalk = SecureTalkInitiator(crypto: self.preferences.crypto, myPrivateKey: self.preferences.myPrivateKey, myIdCard: identityCard, ephPrivateKey: ephPrivateKey, recipientIdCard: identityCardEntry, recipientLtCard: ltCardEntry, recipientOtCard: otCardEntry, wasRecovered: false)
        
        completion(secureTalk, nil)
    }
    
    private func initiateTalk(withRecipientWithCard card: VSSCard, completion: @escaping (SecureTalk?, Error?)->()) throws {
        // FIXME: Check for existing session
        guard let identityCard = self.identityCard else {
            completion(nil, NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Identity card missing. Probably, SecureChat was not initialized."]))
            return
        }
        
        // FIXME: Error handling
        // FIXME: Check is session active
        let session = try self.sessionHelper.getSessionState(forRecipientCardId: card.identifier, crypto: self.preferences.crypto)
        
        if let session = session as? InitiatorSessionState {
            let ephKeyName = session.ephKeyName
            let ephPrivateKey = try self.keyHelper.getEphPrivateKey(withKeyEntryName: ephKeyName)
            
            let identityCardEntry = SecureTalk.CardEntry(identifier: identityCard.identifier, publicKeyData: identityCard.publicKeyData)
            let ltCardEntry = SecureTalk.CardEntry(identifier: session.recipientLongTermCardId, publicKeyData: session.recipientLongTermPublicKey)
            let otCardEntry = SecureTalk.CardEntry(identifier: session.recipientOneTimeCardId, publicKeyData: session.recipientOneTimePublicKey)
            
            let secureTalk = SecureTalkInitiator(crypto: self.preferences.crypto, myPrivateKey: self.preferences.myPrivateKey, myIdCard: identityCard, ephPrivateKey: ephPrivateKey, recipientIdCard: identityCardEntry, recipientLtCard: ltCardEntry, recipientOtCard: otCardEntry, wasRecovered: true)
            
            completion(secureTalk, nil)
        }
        else if let session = session as? ResponderSessionState {
//            let initiatorCardEntry = SecureTalk.CardEntry(identifier: session., publicKeyData: <#T##Data#>)
//            SecureTalkResponder(crypto: self.preferences.crypto, myPrivateKey: self.preferences.myPrivateKey, secureChatKeyHelper: self.keyHelper, initiatorCardEntry: <#T##SecureTalk.CardEntry#>)
            
            
            // FIXME
        }
        else {
            //FIXME
        }
    }
    
    public func initiateTalk(withRecipientWithCardId cardId: String, completion: @escaping (SecureTalk?, Error?)->()) throws {
        self.virgilClient.getCard(withId: cardId) { card, error in
            guard error == nil else {
                completion(nil, error)
                return
            }
            
            guard let recipientIdentityCard = card else {
                completion(nil, NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error obtaining recipient card."]))
                return
            }
            
            do {
                try self.initiateTalk(withRecipientWithCard: recipientIdentityCard) { secureTalk, error in
                    completion(secureTalk, error)
                    
                }
            }
            catch {
                // FIXME
            }
        }
    }
    
    // FIXME optimize calls when backend will be updated
    public func initiateTalk(withRecipientWithIdentity identity: String, completion: @escaping (SecureTalk?, Error?)->()) {
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
                try self.initiateTalk(withCardsSet: cardsSet) { secureTalk, error in
                    completion(secureTalk, error)
                }
            }
            catch {
                // FIXME
            }
        }
    }
}

// MARK: Talk responding
extension SecureChat {
    private func respondToTalk(withCard card: VSSCard, completion: @escaping (SecureTalk?, Error?)->()) {
        let cardEntry = SecureTalk.CardEntry(identifier: card.identifier, publicKeyData: card.publicKeyData)
        let secureTalk = SecureTalkResponder(crypto: self.preferences.crypto, myPrivateKey: self.preferences.myPrivateKey, secureChatKeyHelper: self.keyHelper, initiatorCardEntry: cardEntry, wasRecovered: false)
        
        completion(secureTalk, nil)
    }
    
    public func respondToTalk(withInitiatorWithCardId cardId: String, completion: @escaping (SecureTalk?, Error?)->()) {
        // FIXME: Check for existing session
        // FIXME: Add otc key on new session
        
        self.virgilClient.getCard(withId: cardId) { card, error in
            guard error == nil else {
                completion(nil, NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error obtaining initiator identity card."]))
                return
            }
            
            guard let card = card else {
                completion(nil, NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid initiator identity card."]))
                return
            }
            
            self.respondToTalk(withCard: card) { secureTalk, error in
                completion(secureTalk, error)
            }
        }
    }
}

// MARK: Initialization
extension SecureChat {
    // Workaround for Swift bug SR-2444
    public typealias CompletionHandler = (Error?) -> ()
    
    private static let SecondsInDay: TimeInterval = 24 * 60 * 60
    private func removeOldSessions() throws {
        let sessions = try self.sessionHelper.getAllSessions(crypto: self.preferences.crypto)
        
        let date = Date()
        
        var relevantEphKeys: [String] = []
        
        for session in sessions {
            let sessionAge = date.timeIntervalSince1970 - session.value.creationDate.timeIntervalSince1970
            if (sessionAge > TimeInterval(self.preferences.daysSessionLives) * SecureChat.SecondsInDay) {
                // FIXME Remove session
            }
            else {
                if let initiatorSession = session.value as? InitiatorSessionState {
                    relevantEphKeys.append(initiatorSession.ephKeyName)
                }
                else if let responderSession = session.value as? ResponderSessionState {
                    // FIXME
                }
            }
        }
    }
    
    // FIXME: Get all sessions and check status of LT OT keys
    // FIXME: Check status of old keys and remove unneeded keys
    public func initialize(completion: CompletionHandler? = nil) {
        let errorCallback = { (error: Error?) in
            completion?(error)
        }
        
        do {
            try self.removeOldSessions()
        }
        catch {
            // FIXME
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
                    // FIXME: Add longtermcard management
                    do {
                        try self.cardsHelper.addCards(forIdentityCard: identityCard, includeLtcCard: true, numberOfOtcCards: numberOfMissingCards) { error in
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
