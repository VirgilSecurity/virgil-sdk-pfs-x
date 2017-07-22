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
    
    fileprivate let keyHelper: SecureChatKeyHelper
    fileprivate let cardsHelper: SecureChatCardsHelper
    fileprivate let sessionHelper: SecureChatSessionHelper
    
    public init(preferences: SecureChatPreferences) {
        self.preferences = preferences
        self.client = Client(serviceConfig: self.preferences.serviceConfig)
        
        self.keyHelper = SecureChatKeyHelper(crypto: self.preferences.crypto, keyStorage: self.preferences.keyStorage, identityCardId: self.preferences.identityCard.identifier, longTermKeyTtl: self.preferences.longTermKeysTtl)
        self.cardsHelper = SecureChatCardsHelper(crypto: self.preferences.crypto, myPrivateKey: self.preferences.privateKey, client: self.client, deviceManager: self.preferences.deviceManager, keyHelper: self.keyHelper)
        self.sessionHelper = SecureChatSessionHelper(cardId: self.preferences.identityCard.identifier)
        
        super.init()
    }
    
    fileprivate func isSessionStateExpired(now: Date, sessionState: SessionState) -> Bool {
        return (now > sessionState.expirationDate)
    }
}

// MARK: Active session
extension SecureChat {
    public func activeSession(withParticipantWithCardId cardId: String) -> SecureSession? {
        guard case let sessionState?? = try? self.sessionHelper.getSessionState(forRecipientCardId: cardId) else {
            return nil
        }
        
        guard !self.isSessionStateExpired(now: Date(), sessionState: sessionState) else {
            do {
                try self.removeSession(withParticipantWithCardId: cardId)
            }
            catch {
                NSLog("WARNING: Error occured while removing expired session in activeSession")
            }
            return nil
        }
        
        let secureSession = try? self.recoverSession(myIdentityCard: self.preferences.identityCard, sessionState: sessionState)
    
        return secureSession
    }
}

// MARK: Session initiation
extension SecureChat {
    private func startNewSession(withRecipientWithCard recipientCard: VSSCard, recipientCardsSet cardsSet: RecipientCardsSet, additionalData: Data?) throws -> SecureSession {
        let identityCardId = recipientCard.identifier
        let identityPublicKeyData = recipientCard.publicKeyData
        let longTermPublicKeyData = cardsSet.longTermCard.publicKeyData
        let oneTimePublicKeyData = cardsSet.oneTimeCard?.publicKeyData
        
        let ephKeyPair = self.preferences.crypto.generateKeyPair()
        let ephPrivateKey = ephKeyPair.privateKey
        
        let ephKeyName: String
        do {
            ephKeyName = try self.keyHelper.persistEphPrivateKey(ephPrivateKey, name: identityCardId)
        }
        catch {
            throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.savingEphemeralKey.rawValue, userInfo: [NSLocalizedDescriptionKey: "Error while saving ephemeral key. Underlying error: \(error.localizedDescription)"])
        }
        
        let validator = EphemeralCardValidator(crypto: self.preferences.crypto)

        do {
            try validator.addVerifier(withId: identityCardId, publicKeyData: identityPublicKeyData)
        }
        catch {
            throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.addingVerifier.rawValue, userInfo: [NSLocalizedDescriptionKey: "Error while adding verifier. Underlying error: \(error.localizedDescription)"])
        }
        
        guard validator.validate(cardResponse: cardsSet.longTermCard.cardResponse) else {
            throw NSError(domain: SecureSession.ErrorDomain, code: SecureChatErrorCode.longTermCardValidation.rawValue, userInfo: [NSLocalizedDescriptionKey: "Responder LongTerm card validation failed."])
        }
        
        if let oneTimeCard = cardsSet.oneTimeCard {
            guard validator.validate(cardResponse: oneTimeCard.cardResponse) else {
                throw NSError(domain: SecureSession.ErrorDomain, code: SecureChatErrorCode.oneTimeCardValidation.rawValue, userInfo: [NSLocalizedDescriptionKey: "Responder OneTime card validation failed."])
            }
        }
        
        let identityCardEntry = SecureSession.CardEntry(identifier: identityCardId, publicKeyData: identityPublicKeyData)
        let ltCardEntry = SecureSession.CardEntry(identifier: cardsSet.longTermCard.identifier, publicKeyData: longTermPublicKeyData)
        
        let otCardEntry: SecureSession.CardEntry?
        if let oneTimeCard = cardsSet.oneTimeCard, let oneTimePublicKeyData = oneTimePublicKeyData {
            otCardEntry = SecureSession.CardEntry(identifier: oneTimeCard.identifier, publicKeyData: oneTimePublicKeyData)
        }
        else {
            otCardEntry = nil
        }
        
        let date = Date()
        let secureSession = try SecureSessionInitiator(crypto: self.preferences.crypto, myPrivateKey: self.preferences.privateKey, sessionHelper: self.sessionHelper, additionalData: additionalData, myIdCard: self.preferences.identityCard, ephPrivateKey: ephPrivateKey, ephPrivateKeyName: ephKeyName, recipientIdCard: identityCardEntry, recipientLtCard: ltCardEntry, recipientOtCard: otCardEntry, wasRecovered: false, creationDate: date, expirationDate: date.addingTimeInterval(self.preferences.sessionTtl))
     
        return secureSession
    }
    
    public func startNewSession(withRecipientWithCard recipientCard: VSSCard, additionalData: Data? = nil, completion: @escaping (SecureSession?, Error?)->()) {
        // Check for existing session state
        let sessionState: SessionState?
        do {
            sessionState = try self.sessionHelper.getSessionState(forRecipientCardId: recipientCard.identifier)
        }
        catch {
            completion(nil, NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.checkingForExistingSession.rawValue, userInfo: [NSLocalizedDescriptionKey: "Error checking for existing session. Underlying error: \(error.localizedDescription)"]))
            return
        }
        
        // If we have existing session
        if let sessionState = sessionState {
            // If session is not expired - return error
            guard self.isSessionStateExpired(now: Date(), sessionState: sessionState) else {
                completion(nil, NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.foundActiveSession.rawValue, userInfo: [NSLocalizedDescriptionKey: "Found active session for given recipient. Try to loadUpSession:, if that fails try to remove session."]))
                return
            }
            
            // If session is expired, just remove old session and create new one
            do {
                try self.removeSession(withParticipantWithCardId: recipientCard.identifier)
            }
            catch {
                completion(nil, NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.removingExpiredSession.rawValue, userInfo: [NSLocalizedDescriptionKey: "Error removing expired session while creating new. Underlying error: \(error.localizedDescription)"]))
                return
            }
        }
        
        // Get recipient's credentials
        self.client.getRecipientCardsSet(forCardsIds: [recipientCard.identifier]) { cardsSets, error in
            guard error == nil else {
                completion(nil, NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.obtainingRecipientCardsSet.rawValue, userInfo: [NSLocalizedDescriptionKey: "Error obtaining recipient cards set. Underlying error: \(error!.localizedDescription)"]))
                return
            }
            
            guard let cardsSets = cardsSets, cardsSets.count > 0 else {
                completion(nil, NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.recipientSetEmpty.rawValue, userInfo: [NSLocalizedDescriptionKey: "Error obtaining recipient cards set. Empty set."]))
                return
            }
            
            // FIXME: Multiple sessions?
            let cardsSet = cardsSets[0]
            
            do {
                let session = try self.startNewSession(withRecipientWithCard: recipientCard, recipientCardsSet: cardsSet, additionalData: additionalData)
                completion(session, nil)
                return
            }
            catch {
                completion(nil, error)
                return
            }
        }
    }
}
// MARK: Session responding
extension SecureChat {
    public func loadUpSession(withParticipantWithCard card: VSSCard, message: String, additionalData: Data? = nil) throws -> SecureSession {
        guard let messageData = message.data(using: .utf8) else {
            throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.invalidMessageString.rawValue, userInfo: [NSLocalizedDescriptionKey: "Invalid message string."])
        }
        
        if let initiationMessage = try? SecureSession.extractInitiationMessage(messageData) {
            // Added new one time card
            try? self.cardsHelper.addCards(forIdentityCard: self.preferences.identityCard, includeLtcCard: false, numberOfOtcCards: 1) { error in
                guard error == nil else {
                    NSLog("WARNING: Error occured while adding new otc in loadUpSession")
                    return
                }
            }
            
            let cardEntry = SecureSession.CardEntry(identifier: card.identifier, publicKeyData: card.publicKeyData)
            
            let date = Date()
            let secureSession = SecureSessionResponder(crypto: self.preferences.crypto, myPrivateKey: self.preferences.privateKey, sessionHelper: self.sessionHelper, additionalData: additionalData, secureChatKeyHelper: self.keyHelper, initiatorCardEntry: cardEntry, creationDate: date, expirationDate: date.addingTimeInterval(self.preferences.sessionTtl))
            
            let _ = try secureSession.decrypt(initiationMessage)
            
            return secureSession
        }
        else if let message = try? SecureSession.extractMessage(messageData) {
            let sessionId = message.sessionId
            
            guard case let sessionState?? = try? self.sessionHelper.getSessionState(forRecipientCardId: card.identifier),
                sessionState.sessionId == sessionId else {
                throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.sessionNotFound.rawValue, userInfo: [NSLocalizedDescriptionKey: "Session not found."])
            }
            
            let session = try self.recoverSession(myIdentityCard: self.preferences.identityCard, sessionState: sessionState)
            
            return session
        }
        else {
            throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.unknownMessageStructure.rawValue, userInfo: [NSLocalizedDescriptionKey: "Unknown message structure."])
        }
    }
}

// MARK: Session recovering
extension SecureChat {
    fileprivate func recoverSession(myIdentityCard: VSSCard, sessionState: SessionState) throws -> SecureSession {
        if let sessionState = sessionState as? InitiatorSessionState {
            return try self.recoverInitiatorSession(myIdentityCard: myIdentityCard, initiatorSessionState: sessionState)
        }
        else if let sessionState = sessionState as? ResponderSessionState {
            return try self.recoverResponderSession(myIdentityCard: myIdentityCard, responderSessionState: sessionState)
        }
        else {
            throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.unknownSessionState.rawValue, userInfo: [NSLocalizedDescriptionKey: "Unknown session state."])
        }
    }
    
    private func recoverInitiatorSession(myIdentityCard: VSSCard, initiatorSessionState: InitiatorSessionState) throws -> SecureSession {
        let ephKeyName = initiatorSessionState.ephKeyName
        let ephPrivateKey: VSSPrivateKey
        do {
            ephPrivateKey = try self.keyHelper.getEphPrivateKey(withKeyEntryName: ephKeyName)
        }
        catch {
            throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.gettingEphemeralKeyFromStorage.rawValue, userInfo: [NSLocalizedDescriptionKey: "Error getting ephemeral key from storage. Underlying error: \(error.localizedDescription)"])
        }
        
        let identityCardEntry = SecureSession.CardEntry(identifier: initiatorSessionState.recipientCardId, publicKeyData: initiatorSessionState.recipientPublicKey)
        let ltCardEntry = SecureSession.CardEntry(identifier: initiatorSessionState.recipientLongTermCardId, publicKeyData: initiatorSessionState.recipientLongTermPublicKey)
        let otCardEntry: SecureSession.CardEntry?
        if let recOtId = initiatorSessionState.recipientOneTimeCardId, let recOtPub = initiatorSessionState.recipientOneTimePublicKey {
            otCardEntry = SecureSession.CardEntry(identifier: recOtId, publicKeyData: recOtPub)
        }
        else {
            otCardEntry = nil
        }
        let additionalData = initiatorSessionState.additionalData
        
        let secureSession = try SecureSessionInitiator(crypto: self.preferences.crypto, myPrivateKey: self.preferences.privateKey, sessionHelper: self.sessionHelper, additionalData: additionalData, myIdCard: myIdentityCard, ephPrivateKey: ephPrivateKey, ephPrivateKeyName: ephKeyName, recipientIdCard: identityCardEntry, recipientLtCard: ltCardEntry, recipientOtCard: otCardEntry, wasRecovered: true, creationDate: initiatorSessionState.creationDate, expirationDate: initiatorSessionState.expirationDate)
        
        return secureSession
    }
    
    private func recoverResponderSession(myIdentityCard: VSSCard, responderSessionState: ResponderSessionState) throws -> SecureSession {
        let initiatorCardEntry = SecureSession.CardEntry(identifier: responderSessionState.recipientIdentityCardId, publicKeyData: responderSessionState.recipientIdentityPublicKey)
        let additionalData = responderSessionState.additionalData
        
        let secureSession = try SecureSessionResponder(crypto: self.preferences.crypto, myPrivateKey: self.preferences.privateKey, sessionHelper: self.sessionHelper, additionalData: additionalData, secureChatKeyHelper: self.keyHelper, initiatorCardEntry: initiatorCardEntry, ephPublicKeyData: responderSessionState.ephPublicKeyData, receiverLtcId: responderSessionState.recipientLongTermCardId, receiverOtcId: responderSessionState.recipientOneTimeCardId, creationDate: responderSessionState.creationDate, expirationDate: responderSessionState.expirationDate)
        
        return secureSession
    }
}

// MARK: Session removal
extension SecureChat {
    public func removeSession(withParticipantWithCardId cardId: String) throws {
        if let sessionState = try self.sessionHelper.getSessionState(forRecipientCardId: cardId) {
            var err: Error?
            do {
                try self.removeSessionKeys(usingSessionState: sessionState)
            }
            catch {
                err = error
            }
            try self.sessionHelper.removeSessionsStates([cardId])
            if let err = err {
                throw err
            }
        }
        else {
            try self.removeSessionKeys(forUnknownSessionWithParticipantWithCardId: cardId)
        }
    }
    
    private func removeSessionKeys(forUnknownSessionWithParticipantWithCardId cardId: String) throws {
        var ephErr, otErr: Error?
        if self.keyHelper.ephKeyExists(ephName: cardId) {
            do {
                try self.keyHelper.removeEphPrivateKey(withName: cardId)
            }
            catch {
                ephErr = error
            }
        }
        if self.keyHelper.otKeyExists(otName: cardId) {
            do {
                try self.keyHelper.removeOneTimePrivateKey(withName: cardId)
            }
            catch {
                otErr = error
            }
        }
        
        if let ephErr = ephErr, let otErr = otErr {
            throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.removingEphAndOtKeys.rawValue, userInfo: [NSLocalizedDescriptionKey: "Error while removing both eph and ot keys: \(ephErr.localizedDescription); \(otErr.localizedDescription)"])
        }
        
        if let ephErr = ephErr {
            throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.removingEphKey.rawValue, userInfo: [NSLocalizedDescriptionKey: "Error while removing eph key: \(ephErr.localizedDescription)"])
        }
        if let otErr = otErr {
            throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.removingOtKey.rawValue, userInfo: [NSLocalizedDescriptionKey: "Error while removing ot key: \(otErr.localizedDescription)"])
        }
    }
    
    private func removeSessionKeys(usingSessionState sessionState: SessionState) throws {
        if let sessionState = sessionState as? InitiatorSessionState {
            return try self.removeSessionKeys(usingInitiatorSessionState: sessionState)
        }
        else if let sessionState = sessionState as? ResponderSessionState {
            return try self.removeSessionKeys(usingResponderSessionState: sessionState)
        }
        else {
            throw NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.unknownSessionState.rawValue, userInfo: [NSLocalizedDescriptionKey: "Unknown session state."])
        }
    }
    
    private func removeSessionKeys(usingInitiatorSessionState sessionState: InitiatorSessionState) throws {
        try self.keyHelper.removePrivateKey(withKeyEntryName: sessionState.ephKeyName)
    }
    
    private func removeSessionKeys(usingResponderSessionState sessionState: ResponderSessionState) throws {
        guard let otCardId = sessionState.recipientOneTimeCardId else {
            // Nothing to remove
            return
        }
        
        try self.keyHelper.removeOneTimePrivateKey(withName: otCardId)
    }
}

// MARK: Initialization
extension SecureChat {
    // Workaround for Swift bug SR-2444
    public typealias CompletionHandler = (Error?) -> ()
    
    private func removeExpiredSessionsStates() throws -> (Set<String>, Set<String>, Set<String>) {
        let sessionsStates = try self.sessionHelper.getAllSessionsStates()
        
        let date = Date()
        
        var relevantEphKeys = Set<String>()
        var relevantLtCards = Set<String>()
        var relevantOtCards = Set<String>()
        
        var expiredSessionsStates = [String]()
        
        for sessionState in sessionsStates {
            if self.isSessionStateExpired(now: date, sessionState: sessionState.value) {
                expiredSessionsStates.append(sessionState.key)
            }
            else {
                if let initiatorSession = sessionState.value as? InitiatorSessionState {
                    relevantEphKeys.insert(initiatorSession.ephKeyName)
                }
                else if let responderSession = sessionState.value as? ResponderSessionState {
                    relevantLtCards.insert(responderSession.recipientLongTermCardId)
                    if let recOtId = responderSession.recipientOneTimeCardId {
                        relevantOtCards.insert(recOtId)
                    }
                }
            }
        }
        
        try self.sessionHelper.removeSessionsStates(expiredSessionsStates)
        
        return (relevantEphKeys, relevantLtCards, relevantOtCards)
    }
    
    private static let SecondsInDay: TimeInterval = 24 * 60 * 60
    private func cleanup(completion: @escaping (Error?)->()) {
        let relevantEphKeys: Set<String>
        let relevantLtCards: Set<String>
        let relevantOtCards: Set<String>
        do {
            (relevantEphKeys, relevantLtCards, relevantOtCards) = try self.removeExpiredSessionsStates()
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
        
        self.client.validateOneTimeCards(forRecipientWithId: self.preferences.identityCard.identifier, cardsIds: otKeys) { exhaustedCardsIds, error in
            guard error == nil else {
                completion(error)
                return
            }
            
            guard let exhaustedCardsIds = exhaustedCardsIds else {
                completion(NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.oneTimeCardValidation.rawValue, userInfo: [NSLocalizedDescriptionKey: "Error validation OTC."]))
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
        
        var numberOfMissingCards: Int?
        
        var numberOfCompletedOperations = 0
        let numberOfOperations = 2
        let operationCompletedCallback = {
            numberOfCompletedOperations += 1
            
            if numberOfOperations == numberOfCompletedOperations {
                guard let numberOfMissingCards = numberOfMissingCards else {
                    errorCallback(NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.oneOrMoreInitializationOperationsFailed.rawValue, userInfo: [NSLocalizedDescriptionKey: "One or more initialization operations failed."]))
                    return
                }

                if numberOfMissingCards > 0 {
                    let addLtCard = !self.keyHelper.hasRelevantLtKey()
                    do {
                        try self.cardsHelper.addCards(forIdentityCard: self.preferences.identityCard, includeLtcCard: addLtCard, numberOfOtcCards: numberOfMissingCards) { error in
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
        
        // Check ephemeral cards status
        self.client.getCardsStatus(forUserWithCardId: self.preferences.identityCard.identifier) { status, error in
            guard error == nil else {
                errorCallback(error)
                return
            }
            
            guard let status = status else {
                errorCallback(NSError(domain: SecureChat.ErrorDomain, code: SecureChatErrorCode.obtainingCardsStatus.rawValue, userInfo: [NSLocalizedDescriptionKey: "Error obtaining cards status."]))
                return
            }
            
            // Not enough cards, add more
            numberOfMissingCards = max(self.preferences.numberOfActiveOneTimeCards - status.active, 0)
            operationCompletedCallback()
        }
    }
}
