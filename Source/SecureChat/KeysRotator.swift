//
//  KeysRotator.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/23/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

class KeysRotator {
    fileprivate let identityCard: VSSCard
    fileprivate let exhaustedOneTimeCardTtl: TimeInterval
    fileprivate let expiredSessionTtl: TimeInterval
    fileprivate let longTermKeysTtl: TimeInterval
    fileprivate let expiredLongTermCardTtl: TimeInterval
    fileprivate let ephemeralCardsReplenisher: EphemeralCardsReplenisher
    fileprivate let sessionStorageManager: SessionStorageManager
    fileprivate let keyStorageManager: KeyStorageManager
    fileprivate let exhaustInfoManager: ExhaustInfoManager
    fileprivate let client: Client
    fileprivate let mutex = Mutex()
    
    init(identityCard: VSSCard, exhaustedOneTimeCardTtl: TimeInterval, expiredSessionTtl: TimeInterval, longTermKeysTtl: TimeInterval, expiredLongTermCardTtl: TimeInterval, ephemeralCardsReplenisher: EphemeralCardsReplenisher, sessionStorageManager: SessionStorageManager, keyStorageManager: KeyStorageManager, exhaustInfoManager: ExhaustInfoManager, client: Client) {
        self.identityCard = identityCard
        self.exhaustedOneTimeCardTtl = exhaustedOneTimeCardTtl
        self.expiredSessionTtl = expiredSessionTtl
        self.longTermKeysTtl = longTermKeysTtl
        self.expiredLongTermCardTtl = expiredLongTermCardTtl
        self.ephemeralCardsReplenisher = ephemeralCardsReplenisher
        self.sessionStorageManager = sessionStorageManager
        self.keyStorageManager = keyStorageManager
        self.exhaustInfoManager = exhaustInfoManager
        self.client = client
    }
    
    private func updateExhaustInfo(now: Date, exhaustInfo: ExhaustInfo, exhaustedCardsIds: [String]) throws {
        var newOtc = exhaustInfo.otc
        
        newOtc.append(contentsOf: exhaustedCardsIds.map({ ExhaustInfoEntry(identifier: $0, exhaustDate: now) }))
        let newExhaustInfo = ExhaustInfo(otc: newOtc, ltc: exhaustInfo.ltc, sessions: exhaustInfo.sessions)
        
        try self.exhaustInfoManager.saveKeysExhaustInfo(newExhaustInfo)
    }
    
    private static let SecondsInDay: TimeInterval = 24 * 60 * 60
    private func cleanup(completion: @escaping (Error?)->()) {
        Log.debug("Cleanup started.")
        let now = Date()
        
        do {
            let (updatedExhaustInfo, otCardsToCheck) = try self.processExhaustedStuff(now: now)
        
            self.client.validateOneTimeCards(forRecipientWithId: self.identityCard.identifier, cardsIds: otCardsToCheck) { exhaustedCardsIds, error in
                guard error == nil else {
                    completion(error)
                    return
                }
                
                guard let exhaustedCardsIds = exhaustedCardsIds else {
                    completion(SecureChat.makeError(withCode: .oneTimeCardValidation, description: "Error validation OTC."))
                    return
                }
                
                do {
                    try self.updateExhaustInfo(now: now, exhaustInfo: updatedExhaustInfo, exhaustedCardsIds: exhaustedCardsIds)
                }
                catch {
                    completion(error)
                    return
                }
                
                completion(nil)
            }
        }
        catch {
            completion(error)
            return
        }
    }
    
    func rotateKeys(desiredNumberOfCards: Int, completion: @escaping (Error?) -> ()) {
        guard self.mutex.trylock() else {
            Log.debug("Interrupted concurrent keys' rotation")
            
            completion(SecureChat.makeError(withCode: .anotherRotateKeysInProgress, description: "Another rotateKeys call is in progress."))
            return
        }
        
        Log.debug("Started keys' rotation")
        
        let completionWrapper: (Error?) -> () = {
            self.mutex.unlock()
            completion($0)
        }
        
        let cleanupOperation = CleanupOperation(owner: self)
        let cardsStatusOperation = CardsStatusOperation(owner: self, desiredNumberOfCards: desiredNumberOfCards)
        let addNewKeysOperation = AddNewCardsOperation(owner: self)
        let completionOperation = CompletionOperation(completion: completionWrapper)
        
        addNewKeysOperation.addDependency(cardsStatusOperation)
        addNewKeysOperation.addDependency(cleanupOperation)
        completionOperation.addDependency(addNewKeysOperation)
        
        let queue = OperationQueue()
        queue.addOperations([cardsStatusOperation, cleanupOperation, addNewKeysOperation, completionOperation], waitUntilFinished: false)
    }
    
    class CompletionOperation: AsyncOperation {
        private let completion: (Error?)->()
        init(completion: @escaping (Error?)->()) {
            self.completion = completion
            
            super.init()
        }
        
        override func execute() {
            super.execute()
            
            Log.debug("CompletionOperation started.")
            
            self.finish()
        }
        
        override func finish() {
            self.completion(self.error)
            
            super.finish()
        }
    }
    
    class AddNewCardsOperation: AsyncOperation {
        private let owner: KeysRotator
        init(owner: KeysRotator) {
            self.owner = owner
            
            super.init()
        }
        
        override func execute() {
            super.execute()
            
            Log.debug("AddNewCardsOperation started.")
            guard let cardsStatusOperation: CardsStatusOperation = self.findDependency(),
                let numberOfMissingCards = cardsStatusOperation.numberOfMissingCards else {
                    self.fail(withError: SecureChat.makeError(withCode: .oneOrMoreInitializationOperationsFailed, description: "One or more initialization operations failed."))
                    return
            }
            
            let addLtCard = !self.owner.keyStorageManager.hasRelevantLtKey(longTermKeyTtl: self.owner.longTermKeysTtl)
            if numberOfMissingCards > 0 || addLtCard {
                do {
                    try self.owner.ephemeralCardsReplenisher.addCards(includeLtcCard: addLtCard, numberOfOtcCards: numberOfMissingCards) { error in
                        if let error = error {
                            self.fail(withError: error)
                            return
                        }
                        
                        self.finish()
                    }
                }
                catch {
                    self.fail(withError: error)
                }
            }
            else {
                self.finish()
            }
        }
    }
    
    class CardsStatusOperation: AsyncOperation {
        private let owner: KeysRotator
        private let desiredNumberOfCards: Int
        init(owner: KeysRotator, desiredNumberOfCards: Int) {
            self.owner = owner
            self.desiredNumberOfCards = desiredNumberOfCards
            
            super.init()
        }
        
        var numberOfMissingCards: Int?
        
        override func execute() {
            super.execute()
            
            Log.debug("CardsStatusOperation started.")
            self.owner.client.getCardsStatus(forUserWithCardId: self.owner.identityCard.identifier) { status, error in
                if let error = error {
                    self.fail(withError: error)
                    return
                }
                
                if let status = status {
                    self.numberOfMissingCards = max(self.desiredNumberOfCards - status.active, 0)
                    self.finish()
                }
                else {
                    self.fail(withError: SecureChat.makeError(withCode: .obtainingCardsStatus, description: "Error obtaining cards status."))
                }
            }
        }
    }
    
    class CleanupOperation: AsyncOperation {
        private let owner: KeysRotator
        init(owner: KeysRotator) {
            self.owner = owner
            
            super.init()
        }
        
        override func execute() {
            super.execute()
            
            Log.debug("CleanupOperation started.")
            self.owner.cleanup() { error in
                if let error = error {
                    self.fail(withError: error)
                    return
                }
                
                self.finish()
            }
        }
    }
}

fileprivate extension KeysRotator {
    private func removeOrhpanedSessionKeys(sessionKeys: [KeyAttrs], allSessions: [(String, SessionState)]) throws {
        let allSessionsIds = allSessions.map({ $0.1.sessionId })
        
        let orphanedSessionKeysIds = sessionKeys
            .flatMap({
                guard let sessionId = Data(base64Encoded: $0.name) else {
                    return nil
                }
                
                return sessionId
            })
            .filter({ return !allSessionsIds.contains($0) })
        
        if orphanedSessionKeysIds.count > 0 {
            Log.error("WARNING: orphaned session keys found: \(orphanedSessionKeysIds.map({ $0.base64EncodedString() }))")
            try self.keyStorageManager.removeSessionKeys(forSessionsWithIds: orphanedSessionKeysIds)
        }
    }
    
    private func removeExpiredSessions(now: Date, allSessions: [(String, SessionState)], exhaustInfo: inout ExhaustInfo) throws {
        Log.debug("Removing expired sessions.")
        
        let sessionsIds = allSessions.map({ $0.1.sessionId })
        
        // Remove expired sessions
        let sessionInfosToRemove = exhaustInfo.sessions.filter({ $0.exhaustDate.addingTimeInterval(self.expiredSessionTtl) < now && sessionsIds.contains($0.identifier) })
        let sessionIdsToRemove = sessionInfosToRemove.map({ $0.identifier })
        
        try self.keyStorageManager.removeSessionKeys(forSessionsWithIds: sessionIdsToRemove)
        try self.sessionStorageManager.removeSessionsStates(sessionInfosToRemove.map({ ($0.cardId, $0.identifier) }))
        
        // Update sessions info
        let allSessionsUpdated = allSessions.filter({ !sessionIdsToRemove.contains($0.1.sessionId) })
        
        // Update exhaust info:
        var newSessions = exhaustInfo.sessions
        
        // Clear removed keys
        newSessions = newSessions.filter({ !sessionIdsToRemove.contains($0.identifier) })
        
        // Add recently expired keys
        let newSessionsIds = newSessions.map({ $0.identifier })
        let recentlyExpiredSessions = allSessionsUpdated.filter({ $0.1.isExpired(now: now) && !newSessionsIds.contains($0.1.sessionId) })
        newSessions.append(contentsOf: recentlyExpiredSessions.map({ SessionExhaustInfo(identifier: $0.1.sessionId, cardId: $0.0, exhaustDate: now) }))
        
        // Updated exhaust info
        exhaustInfo = ExhaustInfo(otc: exhaustInfo.otc, ltc: exhaustInfo.ltc, sessions: newSessions)
    }
    
    private func removeOrphanedOtcs(now: Date, otKeys: [KeyAttrs], exhaustInfo: inout ExhaustInfo) throws {
        let otKeysIds = otKeys.map({ $0.name })
        // Remove ot keys that have been used some time ago
        let otcIdsToRemove = exhaustInfo.otc
            .filter({ $0.exhaustDate.addingTimeInterval(self.exhaustedOneTimeCardTtl) < now && otKeysIds.contains($0.identifier) })
            .map({ $0.identifier })
        
        if otcIdsToRemove.count > 0 {
            Log.error("WARNING: orphaned otcs found: \(otcIdsToRemove)")
            try self.keyStorageManager.removeOtPrivateKeys(withNames: otcIdsToRemove)
        }
        
        // Updated exhaust info
        var newOtKeys = exhaustInfo.otc
        newOtKeys = newOtKeys.filter({ otcIdsToRemove.contains($0.identifier) })
        exhaustInfo = ExhaustInfo(otc: newOtKeys, ltc: exhaustInfo.ltc, sessions: exhaustInfo.sessions)
    }
    
    private func removeExpiredLtKeys(now: Date, ltKeys: [KeyAttrs], exhaustInfo: inout ExhaustInfo) throws {
        // Remove lt keys that have expired some time ago
        let ltcIdsToRemove = exhaustInfo.ltc
            .filter({ $0.exhaustDate.addingTimeInterval(self.expiredLongTermCardTtl) < now })
            .map({ $0.identifier })
        
        try self.keyStorageManager.removeLtPrivateKeys(withNames: ltcIdsToRemove)
        
        // Updated lt keys info
        let ltKeysUpdated = ltKeys.filter({ !ltcIdsToRemove.contains($0.name) })
        
        // Update exhaust info:
        var newLtKeys = exhaustInfo.ltc
        
        // Clear removed keys
        newLtKeys = newLtKeys.filter({ !ltcIdsToRemove.contains($0.identifier) })
        
        // Add lt keys that have expired recently
        let newLtKeysIds = newLtKeys.map({ $0.identifier })
        let recentlyExpiredLtKeys = ltKeysUpdated.filter({ $0.creationDate.addingTimeInterval(self.longTermKeysTtl) < now && !newLtKeysIds.contains($0.name) })
        newLtKeys.append(contentsOf: recentlyExpiredLtKeys.map({ ExhaustInfoEntry(identifier: $0.name, exhaustDate: now) }))
        
        // Update exhaust info
        exhaustInfo = ExhaustInfo(otc: exhaustInfo.otc, ltc: newLtKeys, sessions: exhaustInfo.sessions)
    }
    
    func processExhaustedStuff(now: Date) throws -> (ExhaustInfo, [String]) {
        var exhaustInfo = try self.exhaustInfoManager.getKeysExhaustInfo()
        let allSessionStates = try self.sessionStorageManager.getAllSessionsStates()
        let (sessionKeys, ltKeys, otKeys) = try self.keyStorageManager.getAllKeysAttrs()
        
        try self.removeExpiredLtKeys(now: now, ltKeys: ltKeys, exhaustInfo: &exhaustInfo)
        try self.removeOrphanedOtcs(now: now, otKeys: otKeys, exhaustInfo: &exhaustInfo)
        
        let newOtKeysIds = exhaustInfo.otc.map({ $0.identifier })
        let otKeysIdsToCheck = otKeys
            .filter({ !newOtKeysIds.contains($0.name) })
            .map({ $0.name })
        
        try self.removeExpiredSessions(now: now, allSessions: allSessionStates, exhaustInfo: &exhaustInfo)
        try self.removeOrhpanedSessionKeys(sessionKeys: sessionKeys, allSessions: allSessionStates)
        
        return (exhaustInfo, otKeysIdsToCheck)
    }
}
