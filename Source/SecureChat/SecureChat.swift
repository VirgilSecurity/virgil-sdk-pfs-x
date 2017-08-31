//
//  SecureChat.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/20/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

/// Class used to manage SecureSession for specified user
@objc(VSPSecureChat) public class SecureChat: NSObject {
    /// Error domain for NSError instances thrown from here
    public static let ErrorDomain = "VSPSecureChatErrorDomain"
    
    /// User's identity card identifier
    public let identityCardId: String
    
    fileprivate let client: Client
    fileprivate let ephemeralCardsReplenisher: EphemeralCardsReplenisher
    fileprivate let sessionManager: SessionManager
    fileprivate let rotator: KeysRotator
    fileprivate let insensitiveDataStorage: InsensitiveDataStorage
    
    fileprivate let migrationManager: MigrationManager
    
    /// Initializer
    ///
    /// - Parameter preferences: SecureChatPreferences instance
    public init(preferences: SecureChatPreferences) {
        self.identityCardId = preferences.identityCard.identifier
        self.client = preferences.client
        self.insensitiveDataStorage = preferences.insensitiveDataStorage
        
        let keyStorageManager = KeyStorageManager(crypto: preferences.crypto, keyStorage: preferences.keyStorage, identityCardId: preferences.identityCard.identifier)
        self.ephemeralCardsReplenisher = EphemeralCardsReplenisher(crypto: preferences.crypto, identityPrivateKey: preferences.identityPrivateKey, identityCardId: preferences.identityCard.identifier, client: self.client, keyStorageManager: keyStorageManager)
        
        let sessionStorageManager = SessionStorageManager(cardId: preferences.identityCard.identifier, storage: preferences.insensitiveDataStorage)
        
        let exhaustInfoManager = ExhaustInfoManager(cardId: preferences.identityCard.identifier, storage: preferences.insensitiveDataStorage)
        
        let sessionInitializer = SessionInitializer(crypto: preferences.crypto, identityPrivateKey: preferences.identityPrivateKey, identityCard: preferences.identityCard)
        self.sessionManager = SessionManager(identityCard: preferences.identityCard, identityPrivateKey: preferences.identityPrivateKey, crypto: preferences.crypto, sessionTtl: preferences.sessionTtl, keyStorageManager: keyStorageManager, sessionStorageManager: sessionStorageManager, sessionInitializer: sessionInitializer)
        
        self.rotator = KeysRotator(identityCard: preferences.identityCard, exhaustedOneTimeCardTtl: preferences.exhaustedOneTimeKeysTtl, expiredSessionTtl: preferences.expiredSessionTtl, longTermKeysTtl: preferences.longTermKeysTtl, expiredLongTermCardTtl: preferences.expiredLongTermKeysTtl, ephemeralCardsReplenisher: self.ephemeralCardsReplenisher, sessionStorageManager: sessionStorageManager, keyStorageManager: keyStorageManager, exhaustInfoManager: exhaustInfoManager, client: self.client)
        
        self.migrationManager = MigrationManager(crypto: preferences.crypto, identityPrivateKey: preferences.identityPrivateKey, identityCard: preferences.identityCard, keyStorage: preferences.keyStorage, keyStorageManager: keyStorageManager, storage: preferences.insensitiveDataStorage, sessionInitializer: sessionInitializer, sessionManager: sessionManager)
        
        super.init()
    }
    
    class func makeError(withCode code: SecureChatErrorCode, description: String) -> NSError {
        return NSError(domain: SecureChat.ErrorDomain, code: code.rawValue, userInfo: [NSLocalizedDescriptionKey: description])
    }
}

// MARK: - Initialization
extension SecureChat {
    /// Initializes SecureChat
    ///
    /// - Parameter migrateAutomatically: allow automatic migration
    /// - Throws: NSError instances with corresponding description
    public func initialize(migrateAutomatically: Bool = true) throws {
        if migrateAutomatically {
            try self.migrate()
        }
    }
}

// MARK: - Migration
extension SecureChat {
    /// Migrates
    ///
    /// - Throws: NSError instances with corresponding description
    public func migrate() throws {
        let previousVersion = self.getPreviousVersion()
        
        try self.migrate(fromVersion: previousVersion)
        
        // Update version
        try self.insensitiveDataStorage.storeValue(Version.currentVersion.rawValue, forKey: self.getVersionKey())
    }
    
    private func migrate(fromVersion previousVersion: Version) throws {
        let migrationVersions = Version.getSortedVersions(fromVersion: previousVersion)
        
        Log.debug("Versions to migrate: \(migrationVersions.map({ $0.rawValue }))")
        
        for migrationVersion in migrationVersions {
            switch migrationVersion {
            case .v1_0: break
            case .v1_1: try self.migrationManager.migrateToV1_1()        
            }
        }
    }
    
    private func getVersionKey() -> String {
        return "VIRGIL.OWNER=\(self.identityCardId).VERSION"
    }
    
    /// Returns previous version for this SecureChat
    ///
    /// - Returns: previous version
    public func getPreviousVersion() -> Version {
        guard let versionStr = self.insensitiveDataStorage.loadValue(forKey: self.getVersionKey()) as? String,
            let version = Version(rawValue: versionStr) else {
                return .v1_0
        }
        
        return version
    }
    
    /// Version enum
    ///
    /// - v1_0: version 1.0.x
    /// - v1_1: version 1.1.x
    public enum Version: String {
        case v1_0 = "1.0"
        case v1_1 = "1.1"
        
        static func getSortedVersions(fromVersion version: Version) -> [Version] {
            switch version {
            case .v1_0: return [.v1_1]
            case .v1_1: return []
            }
        }
        
        /// Current version
        public static let currentVersion = Version.v1_1
    }
}

// MARK: - Active session
extension SecureChat {
    /// Returns latest active session with specified participant, if present
    ///
    /// - Parameter cardId: Participant's Virgil Card identifier
    /// - Returns: SecureSession if session is found, nil otherwise
    public func activeSession(withParticipantWithCardId cardId: String) -> SecureSession? {
        Log.debug("SecureChat:\(self.identityCardId). Searching for active session for: \(cardId)")
        
        return self.sessionManager.activeSession(withParticipantWithCardId: cardId)
    }
}

// MARK: - Session initiation
extension SecureChat {
    private func startNewSession(withRecipientWithCard recipientCard: VSSCard, recipientCardsSet cardsSet: RecipientCardsSet, additionalData: Data?) throws -> SecureSession {
        Log.debug("SecureChat:\(self.identityCardId). Starting new session with cards set with: \(recipientCard.identifier)")
        
        return try self.sessionManager.initializeInitiatorSession(withRecipientWithCard: recipientCard, recipientCardsSet: cardsSet, additionalData: additionalData)
    }
    
    /// Starts new session with given recipient
    ///
    /// - Parameters:
    ///   - recipientCard: Recipient's identity Virgil Card. WARNING: Identity Card should be validated before getting here!
    ///   - additionalData: Data for additional authorization (e.g. concatenated usernames). AdditionalData should be equal on both participant sides. AdditionalData should be constracted on both sides independently and should NOT be transmitted for security reasons.
    ///   - completion: Completion handler with initialized SecureSession or Error
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

// MARK: - Session responding
extension SecureChat {
    /// Loads existing session using with given participant using received  message
    ///
    /// - Parameters:
    ///   - card: Participant's identity Virgil Card. WARNING: Identity Card should be validated before getting here!
    ///   - message: Received message from this participant
    ///   - additionalData: Data for additional authorization (e.g. concatenated usernames). AdditionalData should be equal on both participant sides. AdditionalData should be constracted on both sides independently and should NOT be transmitted for security reasons.
    /// - Returns: Initialized SecureSession
    /// - Throws: Throws NSError instances with corresponding descriptions
    public func loadUpSession(withParticipantWithCard card: VSSCard, message: String, additionalData: Data? = nil) throws -> SecureSession {
        Log.debug("SecureChat:\(self.identityCardId). Loading session with: \(card.identifier)")
        
        guard let messageData = message.data(using: .utf8) else {
            throw SecureChat.makeError(withCode: .invalidMessageString, description: "Invalid message string.")
        }
        
        if let initiationMessage = try? SecureSession.extractInitiationMessage(fromData: messageData) {
            // Add new one time card if we have received strong session
            if initiationMessage.responderOtcId != nil {
                try? self.ephemeralCardsReplenisher.addCards(includeLtcCard: false, numberOfOtcCards: 1) { error in
                    guard error == nil else {
                        Log.error("SecureChat:\(self.identityCardId). WARNING: Error occured while adding new otc in loadUpSession")
                        return
                    }
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

// MARK: - Keys rotation
extension SecureChat {
    /// Periodic Keys processing.
    ///
    /// This method:
    ///   1. Removes expired long-terms keys and adds new if needed
    ///   2. Removes orphances one-time keys
    ///   3. Removes expired sessions
    ///   4. Removes orphaned session keys
    ///   5. Adds new one-time keys if needed
    ///
    /// WARNING:
    ///   This method is called during initialization.
    ///   It's up to you to call this method after that periodically, since iOS app can stay in memory for any period of time without restarting.
    ///   Recommended period: 24h.
    ///
    /// - Parameters:
    ///   - desiredNumberOfCards: desired number of one-time cards
    ///   - completion: Completion handler with corresponding error if something went wrong
    public func rotateKeys(desiredNumberOfCards: Int, completion: @escaping (Error?) -> ()) {
        self.rotator.rotateKeys(desiredNumberOfCards: desiredNumberOfCards, completion: completion)
    }
}

// MARK: - Session removal
extension SecureChat {
    /// Removes all sessions with given participant
    ///
    /// - Parameter cardId: Participant's identity Virgil Card identifier
    /// - Throws: NSError with corresponding decription
    public func removeSessions(withParticipantWithCardId cardId: String) throws {
        try self.sessionManager.removeSessions(withParticipantWithCardId: cardId)
    }
    
    /// Removes session with given participant and session identifier
    ///
    /// - Parameters:
    ///   - cardId: Participant's identity Virgil Card identifier
    ///   - sessionId: Session identifier
    /// - Throws: NSError with corresponding decription
    public func removeSession(withParticipantWithCardId cardId: String, sessionId: Data) throws {
        try self.sessionManager.removeSession(withParticipantWithCardId: cardId, sessionId: sessionId)
    }
}

// MARK: - Gentle reset
extension SecureChat {
    /// Removes all pfs-related data
    ///
    /// - Throws: NSError with corresponding decription
    public func gentleReset() throws {
        try self.sessionManager.gentleReset()
    }
}
