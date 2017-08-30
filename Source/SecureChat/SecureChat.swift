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
    
    public let identityCardId: String
    public let client: Client
    
    fileprivate let ephemeralCardsReplenisher: EphemeralCardsReplenisher
    fileprivate let sessionManager: SessionManager
    fileprivate let rotator: KeysRotator
    
    public init(preferences: SecureChatPreferences) {
        self.identityCardId = preferences.identityCard.identifier
        self.client = preferences.client
        
        let keyStorageManager = KeyStorageManager(crypto: preferences.crypto, keyStorage: preferences.keyStorage, identityCardId: preferences.identityCard.identifier)
        self.ephemeralCardsReplenisher = EphemeralCardsReplenisher(crypto: preferences.crypto, identityPrivateKey: preferences.identityPrivateKey, identityCardId: preferences.identityCard.identifier, client: self.client, keyStorageManager: keyStorageManager)
        
        let sessionStorageManager = SessionStorageManager(cardId: preferences.identityCard.identifier, storage: preferences.insensitiveDataStorage)
        
        let exhaustInfoManager = ExhaustInfoManager(cardId: preferences.identityCard.identifier, storage: preferences.insensitiveDataStorage)
        
        self.sessionManager = SessionManager(identityCard: preferences.identityCard, identityPrivateKey: preferences.identityPrivateKey, crypto: preferences.crypto, sessionTtl: preferences.sessionTtl, keyStorageManager: keyStorageManager, sessionStorageManager: sessionStorageManager)
        
        self.rotator = KeysRotator(identityCard: preferences.identityCard, exhaustedOneTimeCardTtl: preferences.exhaustedOneTimeKeysTtl, expiredSessionTtl: preferences.expiredSessionTtl, longTermKeysTtl: preferences.longTermKeysTtl, expiredLongTermCardTtl: preferences.expiredLongTermKeysTtl, ephemeralCardsReplenisher: self.ephemeralCardsReplenisher, sessionStorageManager: sessionStorageManager, keyStorageManager: keyStorageManager, exhaustInfoManager: exhaustInfoManager, client: self.client)
        
        super.init()
    }
    
    class func makeError(withCode code: SecureChatErrorCode, description: String) -> NSError {
        return NSError(domain: SecureChat.ErrorDomain, code: code.rawValue, userInfo: [NSLocalizedDescriptionKey: description])
    }
}

// MARK: Active session
extension SecureChat {
    public func activeSession(withParticipantWithCardId cardId: String) -> SecureSession? {
        Log.debug("SecureChat:\(self.identityCardId). Searching for active session for: \(cardId)")
        
        return self.sessionManager.activeSession(withParticipantWithCardId: cardId)
    }
}

// MARK: Session initiation
extension SecureChat {
    private func startNewSession(withRecipientWithCard recipientCard: VSSCard, recipientCardsSet cardsSet: RecipientCardsSet, additionalData: Data?) throws -> SecureSession {
        Log.debug("SecureChat:\(self.identityCardId). Starting new session with cards set with: \(recipientCard.identifier)")
        
        return try self.sessionManager.initializeInitiatorSession(withRecipientWithCard: recipientCard, recipientCardsSet: cardsSet, additionalData: additionalData)
    }
    
    public func startNewSession(withRecipientWithCard recipientCard: VSSCard, additionalData: Data? = nil, completion: @escaping (SecureSession?, Error?)->()) {
        Log.debug("SecureChat:\(self.identityCardId). Starting new session with: \(recipientCard.identifier)")
        
        do {
            try self.sessionManager.checkExistingSessionOnStart(recipientCardId: recipientCard.identifier)
        }
        catch {
            completion(nil, error)
            return
        }
        
        // Get recipient's credentials
        self.client.getRecipientCardsSet(forCardsIds: [recipientCard.identifier]) { cardsSets, error in
            guard error == nil else {
                completion(nil, SecureChat.makeError(withCode: .obtainingRecipientCardsSet, description: "Error obtaining recipient cards set. Underlying error: \(error!.localizedDescription)"))
                return
            }
            
            guard let cardsSets = cardsSets, cardsSets.count > 0 else {
                completion(nil, SecureChat.makeError(withCode: .recipientSetEmpty, description: "Error obtaining recipient cards set. Empty set."))
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
        Log.debug("SecureChat:\(self.identityCardId). Loading session with: \(card.identifier)")
        
        guard let messageData = message.data(using: .utf8) else {
            throw SecureChat.makeError(withCode: .invalidMessageString, description: "Invalid message string.")
        }
        
        if let initiationMessage = try? SecureSession.extractInitiationMessage(fromData: messageData) {
            // Add new one time card
            try? self.ephemeralCardsReplenisher.addCards(includeLtcCard: false, numberOfOtcCards: 1) { error in
                guard error == nil else {
                    Log.error("SecureChat:\(self.identityCardId). WARNING: Error occured while adding new otc in loadUpSession")
                    return
                }
            }
            
            let cardEntry = CardEntry(identifier: card.identifier, publicKeyData: card.publicKeyData)
            
            return try self.sessionManager.initializeResponderSession(initiatorCardEntry: cardEntry, initiationMessage: initiationMessage, additionalData: additionalData)
        }
        else if let message = try? SecureSession.extractMessage(fromData: messageData) {
            let sessionId = message.sessionId
            
            return try self.sessionManager.loadSession(recipientCardId: card.identifier, sessionId: sessionId)
        }
        else {
            throw SecureChat.makeError(withCode: .unknownMessageStructure, description: "Unknown message structure.")
        }
    }
}

// MARK: Keys rotation
extension SecureChat {
    // Workaround for Swift bug SR-2444
    public typealias CompletionHandler = (Error?) -> ()
    
    public func rotateKeys(desiredNumberOfCards: Int, completion: CompletionHandler? = nil) {
        self.rotator.rotateKeys(desiredNumberOfCards: desiredNumberOfCards, completion: completion)
    }
}

extension SecureChat {
    public func removeSessions(withParticipantWithCardId cardId: String) throws {
        try self.sessionManager.removeSessions(withParticipantWithCardId: cardId)
    }
}

extension SecureChat {
    public func gentleReset() throws {
        try self.sessionManager.gentleReset()
    }
}
