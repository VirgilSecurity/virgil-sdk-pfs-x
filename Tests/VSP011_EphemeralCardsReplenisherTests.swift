//
//  VSP011_EphemeralCardsReplenisherTests.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/29/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
@testable import VirgilSDKPFS
import XCTest

class VSP011_EphemeralCardsReplenisherTests: XCTestCase {
    private var cardsReplenisher: EphemeralCardsReplenisher!
    private var client: Client!
    private var utils: VSPTestUtils!
    private var crypto: VSSCryptoProtocol!
    private var virgilClient: VSSClient!
    private var keyStorageManager: KeyStorageManager!

    override func setUp() {
        let consts = VSPTestsConst()
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
        
        let config = ServiceConfig(token: consts.applicationToken, ephemeralServiceURL: consts.pfsServiceURL)
        self.client = Client(serviceConfig: config)
    }
    
    private func initializerReplenisher(privateKey: VSSPrivateKey, card: VSSCard) {
        self.keyStorageManager = KeyStorageManager(crypto: self.crypto, keyStorage: KeychainKeyStorage(), identityCardId: card.identifier)
        
        self.cardsReplenisher = EphemeralCardsReplenisher(crypto: self.crypto, identityPrivateKey: privateKey, identityCardId: card.identifier, client: self.client, deviceManager: VSSDeviceManager(), keyStorageManager: self.keyStorageManager)
    }
    
    func test001_addCards() {
        let ex = self.expectation(description: "")
        
        let numberOfRequests = 7
        let timeout = Double(numberOfRequests) * kEstimatedRequestCompletionTime
        
        let keyPair = self.crypto.generateKeyPair()
        
        let identityRequest = self.utils.instantiateCreateCardRequest(with: keyPair)
        
        self.virgilClient.createCard(with: identityRequest) { card, error in
            self.initializerReplenisher(privateKey: keyPair.privateKey, card: card!)
            
            XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().ot.count == 0)
            XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().lt.count == 0)
            
            let cardId = card!.identifier
            let desiredNumber1 = 0
            let desiredNumber2 = 10
            let desiredNumber3 = 10
            
            try! self.cardsReplenisher.addCards(includeLtcCard: true, numberOfOtcCards: desiredNumber1) { error in
                XCTAssert(error == nil)
                
                XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().ot.count == desiredNumber1)
                XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().lt.count == 1)
                
                self.client.getCardsStatus(forUserWithCardId: cardId) { status, error in
                    XCTAssert(error == nil)
                    
                    XCTAssert(status!.active == desiredNumber1)
                    XCTAssert(status!.exhausted == 0)
                    
                    try! self.cardsReplenisher.addCards(includeLtcCard: true, numberOfOtcCards: desiredNumber2) { error in
                        XCTAssert(error == nil)
                        XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().ot.count == desiredNumber1 + desiredNumber2)
                        XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().lt.count == 2)
                        
                        self.client.getCardsStatus(forUserWithCardId: cardId) { status, error in
                            XCTAssert(error == nil)
                            
                            XCTAssert(status!.active == desiredNumber1 + desiredNumber2)
                            XCTAssert(status!.exhausted == 0)
                            
                            try! self.cardsReplenisher.addCards(includeLtcCard: false, numberOfOtcCards: desiredNumber3) { error in
                                XCTAssert(error == nil)
                                XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().ot.count == desiredNumber1 + desiredNumber2 + desiredNumber3)
                                XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().lt.count == 2)
                                
                                self.client.getCardsStatus(forUserWithCardId: cardId) { status, error in
                                    XCTAssert(error == nil)
                                    
                                    XCTAssert(status!.active == desiredNumber1 + desiredNumber2 + desiredNumber3)
                                    XCTAssert(status!.exhausted == 0)
                                    
                                    ex.fulfill()
                                }
                            }
                        }
                    }
                }
            }
        }
        
        self.waitForExpectations(timeout: timeout)
    }
}
