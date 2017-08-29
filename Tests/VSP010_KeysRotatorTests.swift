//
//  VSP010_KeysRotatorTests.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/29/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
@testable import VirgilSDKPFS
import XCTest

let kEstimatedRequestCompletionTime: TimeInterval = 5

class VSP010_KeysRotatorTests: XCTestCase {
    private var crypto: VSSCryptoProtocol!
    private var utils: VSPTestUtils!
    private var consts: VSPTestsConst!
    private var keysRotator: KeysRotator!
    private var virgilClient: VSSClient!
    
    override func setUp() {
        let consts = VSPTestsConst()
        self.consts = consts
        let crypto = VSSCrypto()
        self.crypto = crypto
        
        self.utils = VSPTestUtils(crypto: crypto, consts: consts)
        
        let virgilConfig = VSSServiceConfig(token: consts.applicationToken)
        let cardValidator = VSSCardValidator(crypto: crypto)
        
        let privateKey = crypto.importPrivateKey(from: Data(base64Encoded: consts.applicationPrivateKeyBase64)!, withPassword: consts.applicationPrivateKeyPassword)!
        let publicKey = crypto.extractPublicKey(from: privateKey)
        let publicKeyData = crypto.export(publicKey)
        
        cardValidator.addVerifier(withId: consts.applicationId, publicKeyData: publicKeyData)
        cardValidator.useVirgilServiceVerifiers = false
        
        virgilConfig.cardValidator = cardValidator
        
        virgilConfig.cardsServiceURL = consts.cardsServiceURL
        virgilConfig.cardsServiceROURL = consts.cardsServiceROURL
        virgilConfig.registrationAuthorityURL = consts.registrationAuthorityURL
        
        self.virgilClient = VSSClient(serviceConfig: virgilConfig)
    }
    
    private func initializeRotator(privateKey: VSSPrivateKey, card: VSSCard) {
        let config = ServiceConfig(token: consts.applicationToken, ephemeralServiceURL: consts.pfsServiceURL)
        let client = Client(serviceConfig: config)
        
        let keyStorageManager = KeyStorageManager(crypto: crypto, keyStorage: KeychainKeyStorage(), identityCardId: card.identifier)
        
        let replenisher = EphemeralCardsReplenisher(crypto: crypto, identityPrivateKey: privateKey, identityCardId: card.identifier, client: client, deviceManager: VSSDeviceManager(), keyStorageManager: keyStorageManager)
        
        let storage = try! UserDefaultsDataStorage.makeStorage(forIdentifier: card.identifier)
        let sessionStorageManager = SessionStorageManager(cardId: card.identifier, storage: storage)
        let exhaustInfoManager = ExhaustInfoManager(cardId: card.identifier, storage: storage)
        
        self.keysRotator = KeysRotator(identityCard: card, exhaustedOneTimeCardTtl: 10, expiredSessionTtl: 10, longTermKeysTtl: 10, expiredLongTermCardTtl: 10, ephemeralCardsReplenisher: replenisher, sessionStorageManager: sessionStorageManager, keyStorageManager: keyStorageManager, exhaustInfoManager: exhaustInfoManager, client: client)
    }
    
    func test001() {
        let ex = self.expectation(description: "")
        
        let numberOfRequests = 3
        let timeout = Double(numberOfRequests) * kEstimatedRequestCompletionTime
        
        let keyPair = self.crypto.generateKeyPair()
        
        let identityRequest = self.utils.instantiateCreateCardRequest(with: keyPair)
        
        self.virgilClient.createCard(with: identityRequest) { card, error in
            self.initializeRotator(privateKey: keyPair.privateKey, card: card!)
            
            self.keysRotator.rotateKeys(desiredNumberOfCards: 10) { error in
                XCTAssert(error == nil)
                
                ex.fulfill()
            }
        }
        
        self.waitForExpectations(timeout: timeout)
    }
    
    func test002_SimultaneousCalls() {
        let ex = self.expectation(description: "")
        
        let numberOfRequests = 1
        let timeout = Double(numberOfRequests) * kEstimatedRequestCompletionTime
        
        let keyPair = self.crypto.generateKeyPair()
        
        let identityRequest = self.utils.instantiateCreateCardRequest(with: keyPair)
        
        self.virgilClient.createCard(with: identityRequest) { card, error in
            self.initializeRotator(privateKey: keyPair.privateKey, card: card!)
            
            self.keysRotator.rotateKeys(desiredNumberOfCards: 10) { error in
                
            }
            
            self.keysRotator.rotateKeys(desiredNumberOfCards: 10) { error in
                XCTAssert(error != nil)
                
                ex.fulfill()
            }
        }
        
        self.waitForExpectations(timeout: timeout)
    }
}
