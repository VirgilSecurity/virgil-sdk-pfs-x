//
//  KeysRotator.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/23/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

class KeysRotator {
    private let cardsHelper: SecureChatCardsHelper
    private let sessionHelper: SecureChatSessionHelper
    private let keyHelper: SecureChatKeyHelper
    private let exhaustHelper: SecureChatExhaustHelper
    private let preferences: SecureChatPreferences
    private let client: Client
    private let mutex: Mutex
    
    init(cardsHelper: SecureChatCardsHelper, sessionHelper: SecureChatSessionHelper, keyHelper: SecureChatKeyHelper, exhaustHelper: SecureChatExhaustHelper, preferences: SecureChatPreferences, client: Client, mutex: Mutex) {
        self.cardsHelper = cardsHelper
        self.sessionHelper = sessionHelper
        self.keyHelper = keyHelper
        self.exhaustHelper = exhaustHelper
        self.preferences = preferences
        self.client = client
        self.mutex = mutex
    }
    
    private func removeExpiredSessions() throws {
        Log.debug("Removing expired sessions.")
        
        let sessionsStates = try self.sessionHelper.getAllSessionsStates()
        
        let date = Date()
        
        let expiredSessionsStates = sessionsStates.filter({ $0.value.isExpired(now: date) })
        
        for sessionState in expiredSessionsStates {
            try self.keyHelper.removeSessionKeys(forSessionWithId: sessionState.value.sessionId)
        }
        
        try self.sessionHelper.removeSessionsStates(withNames: expiredSessionsStates.map({ $0.key }))
    }
    
    private static let SecondsInDay: TimeInterval = 24 * 60 * 60
    private func cleanup(completion: @escaping (Error?)->()) {
        Log.debug("Cleanup started.")
        
        do {
            try self.removeExpiredSessions()
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
        
        let exhaustedInfo: [OtcExhaustInfo]
        do {
            exhaustedInfo = try self.exhaustHelper.getKeysExhaustInfo()
        }
        catch {
            completion(error)
            return
        }
        
        let otcTtl = self.preferences.onetimeCardExhaustLifetime
        let now = Date()
        
        let otcToRemove = Array<String>(exhaustedInfo.filter({ $0.exhaustDate.addingTimeInterval(otcTtl) < now }).map({ $0.cardId }))
        
        for otcId in otcToRemove {
            do {
                try self.keyHelper.removeOtPrivateKey(withName: otcId)
            }
            catch {
                completion(error)
                return
            }
        }
        
        let exhaustedCards = Set<String>(exhaustedInfo.map({ $0.cardId }))
        let otCardsToCheck = Array<String>(Set<String>(otKeys).subtracting(exhaustedCards))
        
        self.client.validateOneTimeCards(forRecipientWithId: self.preferences.identityCard.identifier, cardsIds: otCardsToCheck) { exhaustedCardsIds, error in
            guard error == nil else {
                completion(error)
                return
            }
            
            guard let exhaustedCardsIds = exhaustedCardsIds else {
                completion(SecureChat.makeError(withCode: .oneTimeCardValidation, description: "Error validation OTC."))
                return
            }
            
            var newExhaustInfo = exhaustedInfo.filter({ !otcToRemove.contains($0.cardId) })
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
                    try self.owner.cardsHelper.addCards(forIdentityCard: self.owner.preferences.identityCard, includeLtcCard: addLtCard, numberOfOtcCards: numberOfMissingCards) { error in
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
            self.owner.client.getCardsStatus(forUserWithCardId: self.owner.preferences.identityCard.identifier) { status, error in
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
