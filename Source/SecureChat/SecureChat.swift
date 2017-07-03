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
        
        self.keyHelper = SecureChatKeyHelper(crypto: self.preferences.crypto, keyStorage: self.preferences.keyStorage, identityCardId: self.preferences.myCardId, longTermKeyTtl: self.preferences.longTermKeysTtl)
        self.cardsHelper = SecureChatCardsHelper(crypto: self.preferences.crypto, myPrivateKey: self.preferences.myPrivateKey, client: self.client, deviceManager: self.preferences.deviceManager, keyHelper: self.keyHelper)
        self.sessionHelper = SecureChatSessionHelper(cardId: self.preferences.myCardId)
        
        super.init()
    }
}

// MARK: Talk initiation
extension SecureChat {
    private func initiateTalk(withCardsSet cardsSet: RecipientCardsSet, additionalData: Data?, completion: @escaping (SecureTalk?, Error?)->()) {
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
        
        let ephKeyName: String
        do {
            ephKeyName = try self.keyHelper.persistEphPrivateKey(ephPrivateKey, name: recipientCardId)
        }
        catch {
            completion(nil, NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while saving ephemeral key."]))
            return
        }
        
        if let cardValidator = self.virgilClient.serviceConfig.cardValidator {
            guard cardValidator.validate(cardsSet.identityCard.cardResponse) else {
                completion(nil, NSError(domain: SecureTalk.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Responder identity card validation failed."]))
                return
            }
        }
        
        let validator = EphemeralCardValidator(crypto: self.preferences.crypto)

        do {
            try validator.addVerifier(withId: cardsSet.identityCard.identifier, publicKeyData: cardsSet.identityCard.publicKeyData)
        }
        catch {
            completion(nil, NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while adding verifier."]))
            return
        }
        
        do {
            guard validator.validate(cardResponse: cardsSet.longTermCard.cardResponse) else {
                throw NSError(domain: SecureTalk.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Responder LongTerm card validation failed."])
            }
            guard validator.validate(cardResponse: cardsSet.oneTimeCard.cardResponse) else {
                throw NSError(domain: SecureTalk.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Responder OneTime card validation failed."])
            }
        }
        catch {
            completion(nil, error)
            return
        }
        
        let identityCardEntry = SecureTalk.CardEntry(identifier: cardsSet.identityCard.identifier, publicKeyData: identityPublicKeyData)
        let ltCardEntry = SecureTalk.CardEntry(identifier: cardsSet.longTermCard.identifier, publicKeyData: longTermPublicKeyData)
        let otCardEntry = SecureTalk.CardEntry(identifier: cardsSet.oneTimeCard.identifier, publicKeyData: oneTimePublicKeyData)
        
        let secureTalk: SecureTalk
        do {
            secureTalk = try SecureTalkInitiator(crypto: self.preferences.crypto, myPrivateKey: self.preferences.myPrivateKey, sessionHelper: self.sessionHelper, additionalData: additionalData, myIdCard: identityCard, ephPrivateKey: ephPrivateKey, ephPrivateKeyName: ephKeyName, recipientIdCard: identityCardEntry, recipientLtCard: ltCardEntry, recipientOtCard: otCardEntry, wasRecovered: false, ttl: self.preferences.sessionTtl)
         
            completion(secureTalk, nil)
            return
        }
        catch {
            completion(nil, error)
            return
        }
    }
    
    public func initiateTalk(withRecipientWithCardId cardId: String, additionalData: Data? = nil, completion: @escaping (SecureTalk?, Error?)->()) {
        guard let myIdentityCard = self.identityCard else {
            completion(nil, NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Identity card missing. Probably, SecureChat was not initialized."]))
            return
        }
        
        // FIXME: Check is session active
        let session: SessionState?
        do {
            session = try self.sessionHelper.getSessionState(forRecipientCardId: cardId)
        }
        catch {
            completion(nil, NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error while obtaining save session."]))
            return
        }
        
        if let session = session {
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
                    let secureTalk = try self.recoverTalk(withRecipientWithCard: recipientIdentityCard, myIdentityCard: myIdentityCard, sessionState: session)
                    completion(secureTalk, nil)
                    return
                }
                catch {
                    completion(nil, error)
                    return
                }
            }
        }
        else {
            self.client.getRecipientCardsSet(forCardsIds: [cardId]) { cardsSets, error in
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
                
                self.initiateTalk(withCardsSet: cardsSet, additionalData: additionalData, completion: completion)
            }
        }
    }
}

// MARK: Talk responding
extension SecureChat {
    private func respondToTalk(withCard card: VSSCard, message: Data, additionalData: Data?, completion: @escaping (SecureTalk?, String?, Error?)->()) {
        if let initiationMessage = try? SecureTalk.extractInitiationMessage(message) {
            let cardEntry = SecureTalk.CardEntry(identifier: card.identifier, publicKeyData: card.publicKeyData)
            let secureTalk = SecureTalkResponder(crypto: self.preferences.crypto, myPrivateKey: self.preferences.myPrivateKey, sessionHelper: self.sessionHelper, additionalData: additionalData, ttl: self.preferences.sessionTtl, secureChatKeyHelper: self.keyHelper, initiatorCardEntry: cardEntry)
            
            let message: String
            do {
                message = try secureTalk.decrypt(initiationMessage)
            }
            catch {
                completion(nil, nil, NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error decrypting first message."]))
                return
            }
            
            completion(secureTalk, message, nil)
            return
        }
        else if let message = try? SecureTalk.extractMessage(message) {
            let sessionId = message.sessionId
            
            // FIXME check session expiration
            guard case let session?? = try? self.sessionHelper.getSessionState(forRecipientCardId: card.identifier),
                session.sessionId == sessionId else {
                completion(nil, nil, NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Session not found."]))
                return
            }
            
            let talk: SecureTalk
            do {
                talk = try self.recoverTalk(withRecipientWithCard: card, myIdentityCard: self.identityCard!, sessionState: session)
            }
            catch {
                completion(nil, nil, error)
                return
            }
            
            let decryptedMessage: String
            do {
                decryptedMessage = try talk.decrypt(encryptedMessage: message)
            }
            catch {
                completion(nil, nil, error)
                return
            }
            
            completion(talk, decryptedMessage, nil)
            return
        }
        else {
            completion(nil, nil, NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Unknown message structure."]))
            return
        }
    }
    
    public func respondToTalk(withInitiatorWithCardId cardId: String, message: Data, additionalData: Data? = nil, completion: @escaping (SecureTalk?, String?, Error?)->()) {
        guard let identityCard = self.identityCard else {
            completion(nil, nil, NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Identity card missing. Probably, SecureChat was not initialized."]))
            return
        }
        
        // Added new one time card
        try? self.cardsHelper.addCards(forIdentityCard: identityCard, includeLtcCard: false, numberOfOtcCards: 1) { error in
            // FIXME: handle error?
        }
        
        self.virgilClient.getCard(withId: cardId) { card, error in
            guard error == nil else {
                completion(nil, nil, NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error obtaining initiator identity card."]))
                return
            }
            
            guard let card = card else {
                completion(nil, nil, NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid initiator identity card."]))
                return
            }
            
            self.respondToTalk(withCard: card, message: message, additionalData: additionalData) { secureTalk, decryptedMessage, error in
                completion(secureTalk, decryptedMessage, error)
            }
        }
    }
}

// MARK: Talk recovering
extension SecureChat {
    fileprivate func recoverTalk(withRecipientWithCard card: VSSCard, myIdentityCard: VSSCard, sessionState: SessionState) throws -> SecureTalk {
        if let session = sessionState as? InitiatorSessionState {
            return try self.recoverInitiatorTalk(withRecipientWithCard: card, myIdentityCard: myIdentityCard, initiatorSessionState: session)
        }
        else if let session = sessionState as? ResponderSessionState {
            return try self.recoverResponderTalk(withRecipientWithCard: card, myIdentityCard: myIdentityCard, responderSessionState: session)
        }
        else {
            throw NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Unknown session state."])
        }
    }
    
    private func recoverInitiatorTalk(withRecipientWithCard card: VSSCard, myIdentityCard: VSSCard, initiatorSessionState: InitiatorSessionState) throws -> SecureTalk {
        let ephKeyName = initiatorSessionState.ephKeyName
        let ephPrivateKey: VSSPrivateKey
        do {
            ephPrivateKey = try self.keyHelper.getEphPrivateKey(withKeyEntryName: ephKeyName)
        }
        catch {
            throw NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error getting ephemeral key from storage."])
        }
        
        let identityCardEntry = SecureTalk.CardEntry(identifier: card.identifier, publicKeyData: card.publicKeyData)
        let ltCardEntry = SecureTalk.CardEntry(identifier: initiatorSessionState.recipientLongTermCardId, publicKeyData: initiatorSessionState.recipientLongTermPublicKey)
        let otCardEntry = SecureTalk.CardEntry(identifier: initiatorSessionState.recipientOneTimeCardId, publicKeyData: initiatorSessionState.recipientOneTimePublicKey)
        let additionalData = initiatorSessionState.additionalData
        
        let secureTalk = try SecureTalkInitiator(crypto: self.preferences.crypto, myPrivateKey: self.preferences.myPrivateKey, sessionHelper: self.sessionHelper, additionalData: additionalData, myIdCard: myIdentityCard, ephPrivateKey: ephPrivateKey, ephPrivateKeyName: ephKeyName, recipientIdCard: identityCardEntry, recipientLtCard: ltCardEntry, recipientOtCard: otCardEntry, wasRecovered: true, ttl: self.preferences.sessionTtl)
        
        return secureTalk
    }
    
    private func recoverResponderTalk(withRecipientWithCard card: VSSCard, myIdentityCard: VSSCard, responderSessionState: ResponderSessionState) throws -> SecureTalk {
        let initiatorCardEntry = SecureTalk.CardEntry(identifier: card.identifier, publicKeyData: card.publicKeyData)
        let additionalData = responderSessionState.additionalData
        
        let secureTalk = try SecureTalkResponder(crypto: self.preferences.crypto, myPrivateKey: self.preferences.myPrivateKey, sessionHelper: self.sessionHelper, additionalData: additionalData, ttl: self.preferences.sessionTtl, secureChatKeyHelper: self.keyHelper, initiatorCardEntry: initiatorCardEntry, ephPublicKeyData: responderSessionState.ephPublicKeyData, receiverLtcId: responderSessionState.recipientLongTermCardId, receiverOtcId: responderSessionState.recipientOneTimeCardId)
        
        return secureTalk
    }
}

// MARK: Initialization
extension SecureChat {
    // Workaround for Swift bug SR-2444
    public typealias CompletionHandler = (Error?) -> ()
    
    private static let SecondsInDay: TimeInterval = 24 * 60 * 60
    private func cleanup(completion: @escaping (Error?)->()) {
        let relevantEphKeys: Set<String>
        let relevantLtCards: Set<String>
        let relevantOtCards: Set<String>
        do {
            (relevantEphKeys, relevantLtCards, relevantOtCards) = try self.sessionHelper.removeOldSessions()
        }
        catch {
            completion(error)
            return
        }
        
        let otKeys: [String]
        do {
            otKeys = try self.keyHelper.getAllOtCardsIds()
        }
        catch {
            completion(error)
            return
        }
        
        self.client.validateOneTimeCards(forRecipientWithId: self.preferences.myCardId, cardsIds: otKeys) { exhaustedCardsIds, error in
            guard error == nil else {
                completion(error)
                return
            }
            
            guard let exhaustedCardsIds = exhaustedCardsIds else {
                completion(NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error validation OTC."]))
                return
            }
            
            let relevantOtCards = Set<String>(otKeys).subtracting(Set<String>(exhaustedCardsIds)).union(relevantOtCards)
            
            do {
                try self.keyHelper.removeOldKeys(relevantEphKeys: relevantEphKeys, relevantLtCards: relevantLtCards, relevantOtCards: relevantOtCards)
            }
            catch {
                completion(error)
                return
            }
            
            completion(nil)
        }
    }
    
    public func initialize(completion: CompletionHandler? = nil) {
        var errorHandled = false
        let errorCallback = { (error: Error?) in
            guard errorHandled else {
                errorHandled = true
                completion?(error)
                return
            }
        }
        
        var identityCard: VSSCard?
        var numberOfMissingCards: Int?
        
        var numberOfCompletedOperations = 0
        let numberOfOperations = 3
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
                    let addLtCard = !self.keyHelper.hasRelevantLtKey()
                    do {
                        try self.cardsHelper.addCards(forIdentityCard: identityCard, includeLtcCard: addLtCard, numberOfOtcCards: numberOfMissingCards) { error in
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
        
        self.cleanup() { error in
            guard error == nil else {
                errorCallback(error!)
                return
            }
            
            operationCompletedCallback()
        }
        
        // Get identity card
        self.virgilClient.getCard(withId: self.preferences.myCardId) { card, error in
            guard error == nil else {
                errorCallback(error)
                return
            }
            
            guard let card = card else {
                errorCallback(NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error obtaining identity card."]))
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
                errorCallback(NSError(domain: SecureChat.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error obtaining cards status."]))
                return
            }
            
            // Not enough cards, add more
            numberOfMissingCards = max(self.preferences.numberOfActiveOneTimeCards - status.active, 0)
            operationCompletedCallback()
        }
    }
}
