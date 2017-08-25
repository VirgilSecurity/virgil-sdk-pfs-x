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
    private let cardsHelper: SecureChatCardsHelper
    private let sessionHelper: SecureChatSessionHelper
    private let keyHelper: SecureChatKeyHelper
    private let exhaustHelper: SecureChatExhaustHelper
    private let client: Client
    private let mutex = Mutex()
    
    init(identityCard: VSSCard, oneTimeCardExhaustTtl: TimeInterval, cardsHelper: SecureChatCardsHelper, sessionHelper: SecureChatSessionHelper, keyHelper: SecureChatKeyHelper, exhaustHelper: SecureChatExhaustHelper, client: Client) {
        self.identityCard = identityCard
        self.oneTimeCardExhaustTtl = oneTimeCardExhaustTtl
        self.cardsHelper = cardsHelper
        self.sessionHelper = sessionHelper
        self.keyHelper = keyHelper
        self.exhaustHelper = exhaustHelper
        self.client = client
    }
    
    private func removeExpiredSessionsAndReturnActualSessionIds() throws -> [Data] {
        Log.debug("Removing expired sessions.")
        
        let sessionsStates = try self.sessionHelper.getAllSessionsStates()
        
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
        
        try self.keyHelper.removeSessionKeys(forSessionsWithIds: expiredSessionsIds)
        try self.sessionHelper.removeSessionsStates(dict: expiredSessionsDict)
        
        return actualSessionsStatesIds
    }
    
    private static let SecondsInDay: TimeInterval = 24 * 60 * 60
    private func cleanup(completion: @escaping (Error?)->()) {
        Log.debug("Cleanup started.")
        
        let exhaustedInfo: [OtcExhaustInfo]
        let orphanedOtcIds: Array<String>
        let otCardsToCheck: Array<String>
        let now = Date()
        
        do {
            let actualSessionIds = Set<Data>(try self.removeExpiredSessionsAndReturnActualSessionIds())
        
            let (otKeysIds, sessionKeysIds) = try self.keyHelper.getAllOtCardsAndSessionKeysIds()
            
            let orphanedSessionKeysIds = sessionKeysIds.filter({ !actualSessionIds.contains($0) })
            
            if orphanedSessionKeysIds.count > 0 {
                Log.error("WARNING: orphaned session keys found: \(orphanedSessionKeysIds.map({ $0.base64EncodedString() }))")
                try self.keyHelper.removeSessionKeys(forSessionsWithIds: orphanedSessionKeysIds)
            }

            exhaustedInfo = try self.exhaustHelper.getKeysExhaustInfo()
            
            let otcTtl = self.oneTimeCardExhaustTtl
            
            orphanedOtcIds = exhaustedInfo.filter({ $0.exhaustDate.addingTimeInterval(otcTtl) < now }).map({ $0.cardId })
            
            if orphanedOtcIds.count > 0 {
                Log.error("WARNING: orphaned otcs found: \(orphanedOtcIds)")
                try self.keyHelper.removeOtPrivateKeys(withNames: orphanedOtcIds)
            }
            
            let exhaustedCards = Set<String>(exhaustedInfo.map({ $0.cardId }))
            otCardsToCheck = Array<String>(Set<String>(otKeysIds).subtracting(exhaustedCards))
        }
        catch {
            completion(error)
            return
        }
        
        self.client.validateOneTimeCards(forRecipientWithId: self.identityCard.identifier, cardsIds: otCardsToCheck) { exhaustedCardsIds, error in
            guard error == nil else {
                completion(error)
                return
            }
            
            guard let exhaustedCardsIds = exhaustedCardsIds else {
                completion(SecureChat.makeError(withCode: .oneTimeCardValidation, description: "Error validation OTC."))
                return
            }
            
            var newExhaustInfo = exhaustedInfo.filter({ !orphanedOtcIds.contains($0.cardId) })
            newExhaustInfo.append(contentsOf: exhaustedCardsIds.map({ OtcExhaustInfo(cardId: $0, exhaustDate: now) }))
            
            do {
                try self.exhaustHelper.saveKeysExhaustInfo(newExhaustInfo)
            }
            catch {
                completion(error)
                return
            }
            
            completion(nil)
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
                let addLtCard = !self.owner.keyHelper.hasRelevantLtKey()
                do {
                    try self.owner.cardsHelper.addCards(includeLtcCard: addLtCard, numberOfOtcCards: numberOfMissingCards) { error in
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
