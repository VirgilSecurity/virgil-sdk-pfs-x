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
    private let identityCard: VSSCard
    private let oneTimeCardExhaustTtl: TimeInterval
    private let ephemeralCardsReplenisher: EphemeralCardsReplenisher
    private let sessionStorageManager: SessionStorageManager
    private let keyStorageManager: KeyStorageManager
    private let exhaustInfoManager: ExhaustInfoManager
    private let client: Client
    private let mutex = Mutex()
    
    init(identityCard: VSSCard, oneTimeCardExhaustTtl: TimeInterval, ephemeralCardsReplenisher: EphemeralCardsReplenisher, sessionStorageManager: SessionStorageManager, keyStorageManager: KeyStorageManager, exhaustInfoManager: ExhaustInfoManager, client: Client) {
        self.identityCard = identityCard
        self.oneTimeCardExhaustTtl = oneTimeCardExhaustTtl
        self.ephemeralCardsReplenisher = ephemeralCardsReplenisher
        self.sessionStorageManager = sessionStorageManager
        self.keyStorageManager = keyStorageManager
        self.exhaustInfoManager = exhaustInfoManager
        self.client = client
    }
    
    private func removeExpiredSessionsAndReturnActualSessionIds() throws -> [Data] {
        Log.debug("Removing expired sessions.")
        
        let sessionsStates = try self.sessionStorageManager.getAllSessionsStates()
        
        let date = Date()
        
        var expiredSessionsStates = [String : [Data : SessionState]]()
        var actualSessionsStatesIds = [Data]()
        for sessionState in sessionsStates {
            var expiredSessionsStatesDict = [Data : SessionState]()
            
            for sessionStateDict in sessionState.value {
                if sessionStateDict.value.isExpired(now: date) {
                    expiredSessionsStatesDict[sessionStateDict.key] = sessionStateDict.value
                }
                else {
                    actualSessionsStatesIds.append(sessionStateDict.key)
                }
            }
            
            expiredSessionsStates[sessionState.key] = expiredSessionsStatesDict
        }
        
        let expiredSessionsDict = [String : [Data]](expiredSessionsStates.map({ ($0.key, [Data]($0.value.keys)) }))
        
        if !expiredSessionsDict.isEmpty {
            Log.debug("Found expired sessions.")
        }
        
        let expiredSessionsIds = expiredSessionsDict.reduce([]) { $0 + $1.value }
        
        try self.keyStorageManager.removeSessionKeys(forSessionsWithIds: expiredSessionsIds)
        try self.sessionStorageManager.removeSessionsStates(dict: expiredSessionsDict)
        
        return actualSessionsStatesIds
    }
    
    private func removeOrphanedOtcs(now: Date, otKeysIds: [String]) throws -> ([OtcExhaustInfo], [String]) {
        let exhaustInfo = try self.exhaustInfoManager.getKeysExhaustInfo()
        
        let otcExhaustTtl = self.oneTimeCardExhaustTtl
        
        let orphanedOtcIds = exhaustInfo.filter({ $0.exhaustDate.addingTimeInterval(otcExhaustTtl) < now }).map({ $0.cardId })
        
        let updatedExhaustInfo: [OtcExhaustInfo]
        if orphanedOtcIds.count > 0 {
            Log.error("WARNING: orphaned otcs found: \(orphanedOtcIds)")
            try self.keyStorageManager.removeOtPrivateKeys(withNames: orphanedOtcIds)
            updatedExhaustInfo = exhaustInfo.filter({ !orphanedOtcIds.contains($0.cardId) })
        }
        else {
            updatedExhaustInfo = exhaustInfo
        }
        
        let exhaustedCards = Set<String>(exhaustInfo.map({ $0.cardId }))
        let otCardsToCheck = Array<String>(Set<String>(otKeysIds).subtracting(exhaustedCards))
        
        return (updatedExhaustInfo, otCardsToCheck)
    }
    
    private func removeOrhpanedSessionKeys() throws -> [String] {
        let actualSessionIds = Set<Data>(try self.removeExpiredSessionsAndReturnActualSessionIds())
        
        let (otKeysIds, sessionKeysIds) = try self.keyStorageManager.getAllOtCardsAndSessionKeysIds()
        
        let orphanedSessionKeysIds = sessionKeysIds.filter({ !actualSessionIds.contains($0) })
        
        if orphanedSessionKeysIds.count > 0 {
            Log.error("WARNING: orphaned session keys found: \(orphanedSessionKeysIds.map({ $0.base64EncodedString() }))")
            try self.keyStorageManager.removeSessionKeys(forSessionsWithIds: orphanedSessionKeysIds)
        }
        
        return otKeysIds
    }
    
    private func updateExhaustInfo(now: Date, exhaustInfo: [OtcExhaustInfo], exhaustedCardsIds: [String]) throws {
        var newExhaustInfo = exhaustInfo
        newExhaustInfo.append(contentsOf: exhaustedCardsIds.map({ OtcExhaustInfo(cardId: $0, exhaustDate: now) }))
        
        try self.exhaustInfoManager.saveKeysExhaustInfo(newExhaustInfo)
    }
    
    private static let SecondsInDay: TimeInterval = 24 * 60 * 60
    private func cleanup(completion: @escaping (Error?)->()) {
        Log.debug("Cleanup started.")
        let now = Date()
        
        do {
            try self.keyStorageManager.removeExhaustedLtKeys()
            
            let otKeysIds = try self.removeOrhpanedSessionKeys()
            
            let (updatedExhaustInfo, otCardsToCheck) = try self.removeOrphanedOtcs(now: now, otKeysIds: otKeysIds)
        
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
    
    func rotateKeys(desiredNumberOfCards: Int, completion: SecureChat.CompletionHandler?) {
        guard self.mutex.trylock() else {
            Log.debug("Interrupted concurrent keys' rotation")
            
            completion?(SecureChat.makeError(withCode: .anotherRotateKeysInProgress, description: "Another rotateKeys call is in progress."))
            return
        }
        
        Log.debug("Started keys' rotation")
        
        let completionWrapper: SecureChat.CompletionHandler = {
            self.mutex.unlock()
            completion?($0)
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
        private let completion: SecureChat.CompletionHandler
        init(completion: @escaping SecureChat.CompletionHandler) {
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
            
            if numberOfMissingCards > 0 {
                let addLtCard = !self.owner.keyStorageManager.hasRelevantLtKey()
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
