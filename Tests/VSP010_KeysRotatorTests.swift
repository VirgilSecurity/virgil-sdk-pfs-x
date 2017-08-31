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
    private var client: Client!
    private var keyStorageManager: KeyStorageManager!
    private var sessionStorageManager: SessionStorageManager!
    private var sessionManager: SessionManager!
    private var card, ltCard, otCard: VSSCard!
    
    override func setUp() {
        self.card = VSSCard(data: "eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTI4VDEzOjIzOjI3KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI4ZTFhODVhMDRhMmVmNjJhYzM5MGQ2MmFhOWM0Nzg0OGY1YjBjNzRjZWU5YmY4NjcxZDkyOWNjNTg1NGUwYTRhIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUUdYWEpDVFdpc25cL1VReUNjM0o3WUk3a1QwcEJzUlJqWFZweVlzcDN3aGRtN0p3YlljN2RTVkdSWXdtaEtWODBjSGVKVUw4S0JvNENzT2Uzb3p5RGhRaz0iLCJhNjY2MzE4MDcxMjc0YWRiNzM4YWYzZjY3YjhjN2VjMjlkOTU0ZGUyY2FiZmQ3MWE5NDJlNmVhMzhlNTlmZmY5IjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUURzS3pDQ3Jxb1hlY3Q4V3psVGphRlVXTWkyeEtJYkxKa0Fnd3AyTnBnd3RuYVpoYURsSllMbGh4WDlma25EQTNSRW5nSzBYSExRaG40Zzkxa3NKSmdZPSIsImU2ODBiZWY4N2JhNzVkMzMxYjBhMDJiZmE2YTIwZjAyZWI1YzViYTliYzk2ZmM2MWNhNTk1NDA0YjEwMDI2ZjQiOiJNRkV3RFFZSllJWklBV1VEQkFJQ0JRQUVRRXlobUxHOURiTHBWa3k3c2ttUTVBRTN4T21lMVlpVUpWNjFlemRSZ04rTGlwSmJrclwvclB1VXo3eFJERmUzY294TGM2elRFbUZlK1BqV1BMTnVFcGdrPSJ9fSwiY29udGVudF9zbmFwc2hvdCI6ImV5SndkV0pzYVdOZmEyVjVJam9pVFVOdmQwSlJXVVJMTWxaM1FYbEZRVlZaVTNkQk5XZE9iR2RUVXpSMVQwSlFibmRLVDNOQmFsVkJSSEk1V2xwbFdGWjROakp2YTB0V2RFMDlJaXdpYVdSbGJuUnBkSGtpT2lKQ1JqbEdORFZHUVMwMU9EbEZMVFF6TlRBdE9FVkNRUzAyUWtaRlFVTkNOa05GUTBVaUxDSnBaR1Z1ZEdsMGVWOTBlWEJsSWpvaWRHVnpkQ0lzSW5OamIzQmxJam9pWVhCd2JHbGpZWFJwYjI0aWZRPT0iLCJpZCI6IjhlMWE4NWEwNGEyZWY2MmFjMzkwZDYyYWE5YzQ3ODQ4ZjViMGM3NGNlZTliZjg2NzFkOTI5Y2M1ODU0ZTBhNGEifQ==")!
        
        self.ltCard = VSSCard( data:"eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTI4VDEzOjIzOjI5KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI4ZTFhODVhMDRhMmVmNjJhYzM5MGQ2MmFhOWM0Nzg0OGY1YjBjNzRjZWU5YmY4NjcxZDkyOWNjNTg1NGUwYTRhIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUU1jZWhpXC9ZVXFvZlpVbGdJVmdaRjgzc2ZcL2tObzNNZ0wzQlRmNDVlMWx0eWp1RkhBbWEzMGpCWVBEVDVuY1piQ0gxVXNmekJwbU9US1ZKb2laMXV4ZzQ9IiwiNGYzZWMzY2JlMTFlMTRiY2ZiYjYyNjVhYmYwM2M0YTIxZDYwOThkNGFlZGJjMDZmYjY2OGMyZjYyY2M5M2VmOCI6Ik1GRXdEUVlKWUlaSUFXVURCQUlDQlFBRVFEeFJPWFFCV2ZxWjVYdnhlOWRtUlwvWk40akgrNm90eENxWWY3aFcrcDRaN2VVSFhuUytIbDR4MkZibmtFc2xPZDZ0SHRWTGsrRWNvZnBUUWxPNFRad2s9In19LCJjb250ZW50X3NuYXBzaG90IjoiZXlKd2RXSnNhV05mYTJWNUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFUVktOMU00VEhCS1pETnZTbEJqWEM5bE5HUkxaMHg0U0hCSWRIRnNZM1JhVTFoTlVITkxhVXBDVlhGclBTSXNJbWxrWlc1MGFYUjVJam9pT0dVeFlUZzFZVEEwWVRKbFpqWXlZV016T1RCa05qSmhZVGxqTkRjNE5EaG1OV0l3WXpjMFkyVmxPV0ptT0RZM01XUTVNamxqWXpVNE5UUmxNR0UwWVNJc0ltbGtaVzUwYVhSNVgzUjVjR1VpT2lKcFpHVnVkR2wwZVY5allYSmtYMmxrSWl3aWMyTnZjR1VpT2lKaGNIQnNhV05oZEdsdmJpSXNJbWx1Wm04aU9uc2laR1YyYVdObFgyNWhiV1VpT2lKUGJHVnJjMkZ1WkhMaWdKbHpJRTFoWTBKdmIyc2dVSEp2SWl3aVpHVjJhV05sSWpvaWFWQm9iMjVsSW4xOSIsImlkIjoiMzBmYmVhZWUzZDgyZjM0NjA5NmZhOTliZTAxMzlmNmRiM2U0NzIxZjViNWM5ZWVlNTE0NmUwYTM0ODk4ODVkOSJ9")!
        
        self.otCard = VSSCard(data: "eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTI4VDEzOjIzOjI5KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI4ZTFhODVhMDRhMmVmNjJhYzM5MGQ2MmFhOWM0Nzg0OGY1YjBjNzRjZWU5YmY4NjcxZDkyOWNjNTg1NGUwYTRhIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUU5paGVLTllNR2hKTnMzYzA1ekhuVTBHXC9BMldwY1JqNjNsSm0rVnE5a0lUZXNuSnFrSG04QUM4VW9uc1RZQjJBeHVVYVJaRGNvSjlNenJ2a2o5d0hBbz0iLCI0ZjNlYzNjYmUxMWUxNGJjZmJiNjI2NWFiZjAzYzRhMjFkNjA5OGQ0YWVkYmMwNmZiNjY4YzJmNjJjYzkzZWY4IjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUU5nUGJ3b01DMnRkZkwwXC9hVHZpRmQ3aExiODhoWjVWY1V3Znk2QW9cL09Jamtxc2JySnZ0Tk9EVlRmYnFxQ1BxNXJpaXpsSloxUWxMZCtBQmFQZTFIZzQ9In19LCJjb250ZW50X3NuYXBzaG90IjoiZXlKd2RXSnNhV05mYTJWNUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXcGxVbVpsTjJreGVUUlpVR3B5UkRkMWMzY3lTek5TYTFGRFJpdE9WMnQxTTBWV05sQnBPSHB1WTFrOUlpd2lhV1JsYm5ScGRIa2lPaUk0WlRGaE9EVmhNRFJoTW1WbU5qSmhZek01TUdRMk1tRmhPV00wTnpnME9HWTFZakJqTnpSalpXVTVZbVk0TmpjeFpEa3lPV05qTlRnMU5HVXdZVFJoSWl3aWFXUmxiblJwZEhsZmRIbHdaU0k2SW1sa1pXNTBhWFI1WDJOaGNtUmZhV1FpTENKelkyOXdaU0k2SW1Gd2NHeHBZMkYwYVc5dUlpd2lhVzVtYnlJNmV5SmtaWFpwWTJWZmJtRnRaU0k2SWs5c1pXdHpZVzVrY3VLQW1YTWdUV0ZqUW05dmF5QlFjbThpTENKa1pYWnBZMlVpT2lKcFVHaHZibVVpZlgwPSIsImlkIjoiZDBhZWQzNjdhN2M0ZmE4ZWRhZDBkNjE3ZmU2MDAxNjNjNDMzMTZmOTI5ZTRhMDFlZjExMTBkOTkxYmM0MDA2ZSJ9")!
        
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
        
        let config = ServiceConfig(token: consts.applicationToken, ephemeralServiceURL: consts.pfsServiceURL)
        self.client = Client(serviceConfig: config)
    }
    
    private func initializeRotator(privateKey: VSSPrivateKey, card: VSSCard, exhaustedOneTimeCardTtl: TimeInterval = 100, expiredSessionTtl: TimeInterval = 100, longTermKeysTtl: TimeInterval = 100, expiredLongTermCardTtl: TimeInterval = 100) {
        self.keyStorageManager = KeyStorageManager(crypto: crypto, keyStorage: KeychainKeyStorage(), identityCardId: card.identifier)
        
        let replenisher = EphemeralCardsReplenisher(crypto: crypto, identityPrivateKey: privateKey, identityCardId: card.identifier, client: self.client, keyStorageManager: keyStorageManager)
        
        let storage = try! UserDefaultsDataStorage.makeStorage(forIdentifier: card.identifier)
        let sessionStorageManager = SessionStorageManager(cardId: card.identifier, storage: storage)
        self.sessionStorageManager = sessionStorageManager
        let exhaustInfoManager = ExhaustInfoManager(cardId: card.identifier, storage: storage)
        
        self.keysRotator = KeysRotator(identityCard: card, exhaustedOneTimeCardTtl: exhaustedOneTimeCardTtl, expiredSessionTtl: expiredSessionTtl, longTermKeysTtl: longTermKeysTtl, expiredLongTermCardTtl: expiredLongTermCardTtl, ephemeralCardsReplenisher: replenisher, sessionStorageManager: sessionStorageManager, keyStorageManager: keyStorageManager, exhaustInfoManager: exhaustInfoManager, client: self.client)
    }
    
    private func initializerSessionManager(card: VSSCard, sessionTtl: TimeInterval) {
        let sessionStorageManager = SessionStorageManager(cardId: card.identifier, storage: try! UserDefaultsDataStorage.makeStorage(forIdentifier: card.identifier))
        
        let privateKey = self.crypto.generateKeyPair().privateKey
        let sessionInitializer = SessionInitializer(crypto: self.crypto, identityPrivateKey: privateKey, identityCard: card)
        self.sessionManager = SessionManager(identityCard: card, identityPrivateKey: privateKey, crypto: self.crypto, sessionTtl: sessionTtl, keyStorageManager: self.keyStorageManager, sessionStorageManager: sessionStorageManager, sessionInitializer: sessionInitializer)
    }
    
    func test001_RotateKeys() {
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
    
    func test003_OtcRotation() {
        let ex = self.expectation(description: "")
        
        let numberOfRequests = 8
        let timeout = Double(numberOfRequests) * kEstimatedRequestCompletionTime
        
        let keyPair = self.crypto.generateKeyPair()
        
        let identityRequest = self.utils.instantiateCreateCardRequest(with: keyPair)
        
        self.virgilClient.createCard(with: identityRequest) { card, error in
            self.initializeRotator(privateKey: keyPair.privateKey, card: card!)
            
            let cardId = card!.identifier
            
            self.keysRotator.rotateKeys(desiredNumberOfCards: 10) { error in
                XCTAssert(error == nil)
                
                self.client.getCardsStatus(forUserWithCardId: cardId) { status, error in
                    XCTAssert(error == nil)
                    
                    XCTAssert(status!.active == 10)
                    XCTAssert(status!.exhausted == 0)
                    
                    self.keysRotator.rotateKeys(desiredNumberOfCards: 10) { error in
                        XCTAssert(error == nil)
                        
                        self.client.getCardsStatus(forUserWithCardId: cardId) { status, error in
                            XCTAssert(error == nil)
                            
                            XCTAssert(status!.active == 10)
                            XCTAssert(status!.exhausted == 0)
                            
                            self.keysRotator.rotateKeys(desiredNumberOfCards: 100) { error in
                                XCTAssert(error == nil)
                                
                                self.client.getCardsStatus(forUserWithCardId: cardId) { status, error in
                                    XCTAssert(error == nil)
                                    
                                    XCTAssert(status!.active == 100)
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
    
    func test004_RemoveOrhpanedOtc() {
        let ex = self.expectation(description: "")
        
        let exhaustTime: UInt32 = 10
        let numberOfRequests = 15
        let timeout = Double(numberOfRequests) * kEstimatedRequestCompletionTime + Double(exhaustTime)
        
        let keyPair = self.crypto.generateKeyPair()
        
        let identityRequest = self.utils.instantiateCreateCardRequest(with: keyPair)
        
        self.virgilClient.createCard(with: identityRequest) { card, error in
            self.initializeRotator(privateKey: keyPair.privateKey, card: card!, exhaustedOneTimeCardTtl: TimeInterval(exhaustTime))
            
            let cardId = card!.identifier
            
            self.keysRotator.rotateKeys(desiredNumberOfCards: 10) { error in
                XCTAssert(error == nil)
                
                XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().ot.count == 10)
                
                self.client.getRecipientCardsSet(forCardsIds: [cardId]) { cardsSets, error in
                    XCTAssert(error == nil)
                    XCTAssert(cardsSets!.count == 1)
                    
                    let cardsSet = cardsSets![0]
                    
                    let ltId = cardsSet.longTermCard.identifier
                    let otId = cardsSet.oneTimeCard!.identifier
                    
                    let _ = try! self.keyStorageManager.getOtPrivateKey(withName: otId)
                    let _ = try! self.keyStorageManager.getLtPrivateKey(withName: ltId)
                    
                    self.keysRotator.rotateKeys(desiredNumberOfCards: 10) { error in
                        XCTAssert(error == nil)
                        
                        let _ = try! self.keyStorageManager.getOtPrivateKey(withName: otId)
                        
                        self.keysRotator.rotateKeys(desiredNumberOfCards: 10) { error in
                            XCTAssert(error == nil)
                        
                            let _ = try! self.keyStorageManager.getOtPrivateKey(withName: otId)
                        
                            sleep(exhaustTime)
                            
                            self.keysRotator.rotateKeys(desiredNumberOfCards: 10) { error in
                                XCTAssert(error == nil)
                                
                                var errorWasThrown = false
                                do {
                                    let _ = try self.keyStorageManager.getOtPrivateKey(withName: otId)
                                }
                                catch {
                                    errorWasThrown = true
                                }
                                XCTAssert(errorWasThrown)
                                
                                self.client.getCardsStatus(forUserWithCardId: cardId) { status, error in
                                    XCTAssert(error == nil)
                                    
                                    XCTAssert(status!.active == 10)
                                    XCTAssert(status!.exhausted == 1)
                                    
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
    
    func test005_LtcRotation() {
        let ex = self.expectation(description: "")
        
        let expireTime: UInt32 = 10
        let exhaustTime: UInt32 = 10
        let numberOfRequests = 13
        let timeout = Double(numberOfRequests) * kEstimatedRequestCompletionTime + Double(expireTime) + Double(exhaustTime)
        
        let keyPair = self.crypto.generateKeyPair()
        
        let identityRequest = self.utils.instantiateCreateCardRequest(with: keyPair)
        
        self.virgilClient.createCard(with: identityRequest) { card, error in
            self.initializeRotator(privateKey: keyPair.privateKey, card: card!, longTermKeysTtl: TimeInterval(expireTime), expiredLongTermCardTtl: TimeInterval(exhaustTime))
            
            let cardId = card!.identifier
            
            self.keysRotator.rotateKeys(desiredNumberOfCards: 0) { error in
                XCTAssert(error == nil)
                
                XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().lt.count == 1)
                
                self.client.getRecipientCardsSet(forCardsIds: [cardId]) { cardsSets, error in
                    XCTAssert(error == nil)
                    XCTAssert(cardsSets!.count == 1)
                    
                    let cardsSet = cardsSets![0]
                    
                    XCTAssert(cardsSet.oneTimeCard == nil)
                    
                    let ltId = cardsSet.longTermCard.identifier
                    
                    let _ = try! self.keyStorageManager.getLtPrivateKey(withName: ltId)
                    
                    self.keysRotator.rotateKeys(desiredNumberOfCards: 0) { error in
                        XCTAssert(error == nil)
                        
                        let _ = try! self.keyStorageManager.getLtPrivateKey(withName: ltId)
                        
                        sleep(expireTime)
                        
                        self.keysRotator.rotateKeys(desiredNumberOfCards: 0) { error in
                            XCTAssert(error == nil)
                            
                            let _ = try! self.keyStorageManager.getLtPrivateKey(withName: ltId)
                            
                            sleep(exhaustTime)
                            
                            self.keysRotator.rotateKeys(desiredNumberOfCards: 0) { error in
                                XCTAssert(error == nil)
                                
                                var errorWasThrown = false
                                do {
                                    let _ = try self.keyStorageManager.getLtPrivateKey(withName: ltId)
                                }
                                catch {
                                    errorWasThrown = true
                                }
                                XCTAssert(errorWasThrown)
                                        
                                ex.fulfill()
                            }
                        }
                    }
                }
            }
        }
        
        self.waitForExpectations(timeout: timeout)
    }
    
    func test006_SessionsLifecycle() {
        let ex = self.expectation(description: "")
        
        let expireTime: UInt32 = 10
        let exhaustTime: UInt32 = 10
        let numberOfRequests = 12
        let timeout = Double(numberOfRequests) * kEstimatedRequestCompletionTime + Double(expireTime) + Double(exhaustTime)
        
        let keyPair = self.crypto.generateKeyPair()
        
        let identityRequest = self.utils.instantiateCreateCardRequest(with: keyPair)
        
        self.virgilClient.createCard(with: identityRequest) { card, error in
            self.initializeRotator(privateKey: keyPair.privateKey, card: card!, expiredSessionTtl: TimeInterval(exhaustTime))
            self.initializerSessionManager(card: card!, sessionTtl: TimeInterval(expireTime))
            
            self.keysRotator.rotateKeys(desiredNumberOfCards: 0) { error in
                XCTAssert(error == nil)
                
                XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().session.count == 0)
                XCTAssert(try! self.sessionStorageManager.getAllSessionsStates().count == 0)

                let cardsSet = RecipientCardsSet(longTermCard: self.ltCard, oneTimeCard: self.otCard)
                
                let session = try! self.sessionManager.initializeInitiatorSession(withRecipientWithCard: self.card, recipientCardsSet: cardsSet, additionalData: nil)
                let sessionId = session.identifier
                
                XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().session.count == 1)
                XCTAssert(try! self.sessionStorageManager.getAllSessionsStates().count == 1)
                
                let _ = try! self.keyStorageManager.getSessionKeys(forSessionWithId: sessionId)
                XCTAssert(try! self.sessionStorageManager.getSessionState(forRecipientCardId: self.card.identifier, sessionId: sessionId) != nil)
                
                self.keysRotator.rotateKeys(desiredNumberOfCards: 0) { error in
                    XCTAssert(error == nil)
                    
                    let _ = try! self.keyStorageManager.getSessionKeys(forSessionWithId: sessionId)
                    XCTAssert(try! self.sessionStorageManager.getSessionState(forRecipientCardId: self.card.identifier, sessionId: sessionId) != nil)
                    
                    sleep(expireTime)
                    
                    self.keysRotator.rotateKeys(desiredNumberOfCards: 0) { error in
                        XCTAssert(error == nil)
                        
                        let _ = try! self.keyStorageManager.getSessionKeys(forSessionWithId: sessionId)
                        XCTAssert(try! self.sessionStorageManager.getSessionState(forRecipientCardId: self.card.identifier, sessionId: sessionId) != nil)
                        
                        sleep(exhaustTime)
                        
                        self.keysRotator.rotateKeys(desiredNumberOfCards: 0) { error in
                            XCTAssert(error == nil)
                            
                            var errorWasThrown = false
                            do {
                                let _ = try self.keyStorageManager.getSessionKeys(forSessionWithId: sessionId)
                            }
                            catch {
                                errorWasThrown = true
                            }
                            XCTAssert(errorWasThrown)
                            
                            XCTAssert(try! self.sessionStorageManager.getSessionState(forRecipientCardId: self.card.identifier, sessionId: sessionId) == nil)
                            
                            ex.fulfill()
                        }
                    }
                }
            }
        }
        
        self.waitForExpectations(timeout: timeout)
    }
    
    func test007_OrphanedSessionKeys() {
        let ex = self.expectation(description: "")
        
        let expireTime: UInt32 = 10
        let exhaustTime: UInt32 = 10
        let numberOfRequests = 12
        let timeout = Double(numberOfRequests) * kEstimatedRequestCompletionTime + Double(expireTime) + Double(exhaustTime)
        
        let keyPair = self.crypto.generateKeyPair()
        
        let identityRequest = self.utils.instantiateCreateCardRequest(with: keyPair)
        
        self.virgilClient.createCard(with: identityRequest) { card, error in
            self.initializeRotator(privateKey: keyPair.privateKey, card: card!, expiredSessionTtl: TimeInterval(exhaustTime))
            self.initializerSessionManager(card: card!, sessionTtl: TimeInterval(expireTime))
            
            self.keysRotator.rotateKeys(desiredNumberOfCards: 0) { error in
                XCTAssert(error == nil)
                
                XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().session.count == 0)
                XCTAssert(try! self.sessionStorageManager.getAllSessionsStates().count == 0)
                
                let cardsSet = RecipientCardsSet(longTermCard: self.ltCard, oneTimeCard: self.otCard)
                
                let session = try! self.sessionManager.initializeInitiatorSession(withRecipientWithCard: self.card, recipientCardsSet: cardsSet, additionalData: nil)
                let sessionId = session.identifier
                
                let _ = try! self.sessionStorageManager.removeSessionState(forCardId: self.card.identifier, sessionId: sessionId)
                
                self.keysRotator.rotateKeys(desiredNumberOfCards: 0) { error in
                    XCTAssert(error == nil)
                    
                    XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().session.count == 0)
                    
                    var errorWasThrown = false
                    do {
                        let _ = try self.keyStorageManager.getSessionKeys(forSessionWithId: sessionId)
                    }
                    catch {
                        errorWasThrown = true
                    }
                    XCTAssert(errorWasThrown)
                    
                    ex.fulfill()
                }
            }
        }
        
        self.waitForExpectations(timeout: timeout)
    }
    
    func test008_RemoveOrhpanedOtcUsed() {
        let ex = self.expectation(description: "")
        
        let exhaustTime: UInt32 = 10
        let numberOfRequests = 15
        let timeout = Double(numberOfRequests) * kEstimatedRequestCompletionTime + Double(exhaustTime)
        
        let keyPair = self.crypto.generateKeyPair()
        
        let identityRequest = self.utils.instantiateCreateCardRequest(with: keyPair)
        
        self.virgilClient.createCard(with: identityRequest) { card, error in
            self.initializeRotator(privateKey: keyPair.privateKey, card: card!, exhaustedOneTimeCardTtl: TimeInterval(exhaustTime))
            
            let cardId = card!.identifier
            
            self.keysRotator.rotateKeys(desiredNumberOfCards: 10) { error in
                XCTAssert(error == nil)
                
                XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().ot.count == 10)
                
                self.client.getRecipientCardsSet(forCardsIds: [cardId]) { cardsSets, error in
                    XCTAssert(error == nil)
                    XCTAssert(cardsSets!.count == 1)
                    
                    let cardsSet = cardsSets![0]
                    
                    let ltId = cardsSet.longTermCard.identifier
                    let otId = cardsSet.oneTimeCard!.identifier
                    
                    let _ = try! self.keyStorageManager.getOtPrivateKey(withName: otId)
                    let _ = try! self.keyStorageManager.getLtPrivateKey(withName: ltId)
                    
                    self.keysRotator.rotateKeys(desiredNumberOfCards: 10) { error in
                        XCTAssert(error == nil)
                        
                        let _ = try! self.keyStorageManager.getOtPrivateKey(withName: otId)
                        
                        // Simulate ot key usage
                        try! self.keyStorageManager.removeOtPrivateKey(withName: otId)
                        
                        sleep(exhaustTime)
                        
                        self.keysRotator.rotateKeys(desiredNumberOfCards: 10) { error in
                            XCTAssert(error == nil)
                            
                            ex.fulfill()
                        }
                    }
                }
            }
        }
        
        self.waitForExpectations(timeout: timeout)
    }
    
    func test009_RemoveExhaustedSessionAlreadyRemoved() {
        let ex = self.expectation(description: "")
        
        let expireTime: UInt32 = 10
        let exhaustTime: UInt32 = 10
        let numberOfRequests = 12
        let timeout = Double(numberOfRequests) * kEstimatedRequestCompletionTime + Double(expireTime) + Double(exhaustTime)
        
        let keyPair = self.crypto.generateKeyPair()
        
        let identityRequest = self.utils.instantiateCreateCardRequest(with: keyPair)
        
        self.virgilClient.createCard(with: identityRequest) { card, error in
            self.initializeRotator(privateKey: keyPair.privateKey, card: card!, expiredSessionTtl: TimeInterval(exhaustTime))
            self.initializerSessionManager(card: card!, sessionTtl: TimeInterval(expireTime))
            
            self.keysRotator.rotateKeys(desiredNumberOfCards: 0) { error in
                XCTAssert(error == nil)
                
                XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().session.count == 0)
                XCTAssert(try! self.sessionStorageManager.getAllSessionsStates().count == 0)
                
                let cardsSet = RecipientCardsSet(longTermCard: self.ltCard, oneTimeCard: self.otCard)
                
                let session = try! self.sessionManager.initializeInitiatorSession(withRecipientWithCard: self.card, recipientCardsSet: cardsSet, additionalData: nil)
                let sessionId = session.identifier
                
                XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().session.count == 1)
                XCTAssert(try! self.sessionStorageManager.getAllSessionsStates().count == 1)
                
                let _ = try! self.keyStorageManager.getSessionKeys(forSessionWithId: sessionId)
                XCTAssert(try! self.sessionStorageManager.getSessionState(forRecipientCardId: self.card.identifier, sessionId: sessionId) != nil)
                
                self.keysRotator.rotateKeys(desiredNumberOfCards: 0) { error in
                    XCTAssert(error == nil)
                    
                    let _ = try! self.keyStorageManager.getSessionKeys(forSessionWithId: sessionId)
                    XCTAssert(try! self.sessionStorageManager.getSessionState(forRecipientCardId: self.card.identifier, sessionId: sessionId) != nil)
                    
                    sleep(expireTime)
                    
                    self.keysRotator.rotateKeys(desiredNumberOfCards: 0) { error in
                        XCTAssert(error == nil)
                        
                        try! self.sessionManager.removeSessions(withParticipantWithCardId: self.card.identifier)
                        
                        var errorWasThrown = false
                        do {
                            let _ = try self.keyStorageManager.getSessionKeys(forSessionWithId: sessionId)
                        }
                        catch {
                            errorWasThrown = true
                        }
                        XCTAssert(errorWasThrown)
                        
                        XCTAssert(try! self.sessionStorageManager.getSessionState(forRecipientCardId: self.card.identifier, sessionId: sessionId) == nil)
                        
                        sleep(exhaustTime)
                        
                        self.keysRotator.rotateKeys(desiredNumberOfCards: 0) { error in
                            XCTAssert(error == nil)
                            
                            ex.fulfill()
                        }
                    }
                }
            }
        }
        
        self.waitForExpectations(timeout: timeout)
    }
}
