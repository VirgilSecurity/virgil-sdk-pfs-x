//
//  VSP009_SessionManagerTests.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/28/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
@testable import VirgilSDKPFS
import XCTest

class VSP009_SessionManagerTests: XCTestCase {
    private var crypto: VSSCryptoProtocol!
    private var card: VSSCard!
    private var keyStorageManager: KeyStorageManager!
    private var sessionManager: SessionManager!
    private var sessionTtl: TimeInterval!
    
    override func setUp() {
        self.crypto = VSSCrypto()
        
        self.card = VSSCard(data: "eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTI4VDEzOjIzOjI3KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI4ZTFhODVhMDRhMmVmNjJhYzM5MGQ2MmFhOWM0Nzg0OGY1YjBjNzRjZWU5YmY4NjcxZDkyOWNjNTg1NGUwYTRhIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUUdYWEpDVFdpc25cL1VReUNjM0o3WUk3a1QwcEJzUlJqWFZweVlzcDN3aGRtN0p3YlljN2RTVkdSWXdtaEtWODBjSGVKVUw4S0JvNENzT2Uzb3p5RGhRaz0iLCJhNjY2MzE4MDcxMjc0YWRiNzM4YWYzZjY3YjhjN2VjMjlkOTU0ZGUyY2FiZmQ3MWE5NDJlNmVhMzhlNTlmZmY5IjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUURzS3pDQ3Jxb1hlY3Q4V3psVGphRlVXTWkyeEtJYkxKa0Fnd3AyTnBnd3RuYVpoYURsSllMbGh4WDlma25EQTNSRW5nSzBYSExRaG40Zzkxa3NKSmdZPSIsImU2ODBiZWY4N2JhNzVkMzMxYjBhMDJiZmE2YTIwZjAyZWI1YzViYTliYzk2ZmM2MWNhNTk1NDA0YjEwMDI2ZjQiOiJNRkV3RFFZSllJWklBV1VEQkFJQ0JRQUVRRXlobUxHOURiTHBWa3k3c2ttUTVBRTN4T21lMVlpVUpWNjFlemRSZ04rTGlwSmJrclwvclB1VXo3eFJERmUzY294TGM2elRFbUZlK1BqV1BMTnVFcGdrPSJ9fSwiY29udGVudF9zbmFwc2hvdCI6ImV5SndkV0pzYVdOZmEyVjVJam9pVFVOdmQwSlJXVVJMTWxaM1FYbEZRVlZaVTNkQk5XZE9iR2RUVXpSMVQwSlFibmRLVDNOQmFsVkJSSEk1V2xwbFdGWjROakp2YTB0V2RFMDlJaXdpYVdSbGJuUnBkSGtpT2lKQ1JqbEdORFZHUVMwMU9EbEZMVFF6TlRBdE9FVkNRUzAyUWtaRlFVTkNOa05GUTBVaUxDSnBaR1Z1ZEdsMGVWOTBlWEJsSWpvaWRHVnpkQ0lzSW5OamIzQmxJam9pWVhCd2JHbGpZWFJwYjI0aWZRPT0iLCJpZCI6IjhlMWE4NWEwNGEyZWY2MmFjMzkwZDYyYWE5YzQ3ODQ4ZjViMGM3NGNlZTliZjg2NzFkOTI5Y2M1ODU0ZTBhNGEifQ==")!
        
        self.keyStorageManager = KeyStorageManager(crypto: self.crypto, keyStorage: KeychainKeyStorage(), identityCardId: card.identifier)
        
        let sessionStorageManager = SessionStorageManager(cardId: card.identifier, storage: try! UserDefaultsDataStorage.makeStorage(forIdentifier: card.identifier))
        
        self.sessionTtl = 10
        let privateKey = self.crypto.generateKeyPair().privateKey
        let sessionInitializer = SessionInitializer(crypto: self.crypto, identityPrivateKey: privateKey, identityCard: self.card)
        self.sessionManager = SessionManager(identityCard: self.card, identityPrivateKey: privateKey, crypto: self.crypto, sessionTtl: self.sessionTtl, keyStorageManager: self.keyStorageManager, sessionStorageManager: sessionStorageManager, sessionInitializer: sessionInitializer)
    }
    
    func test001_InitializeInitiator() {
        let ltCard = VSSCard( data:"eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTI4VDEzOjIzOjI5KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI4ZTFhODVhMDRhMmVmNjJhYzM5MGQ2MmFhOWM0Nzg0OGY1YjBjNzRjZWU5YmY4NjcxZDkyOWNjNTg1NGUwYTRhIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUU1jZWhpXC9ZVXFvZlpVbGdJVmdaRjgzc2ZcL2tObzNNZ0wzQlRmNDVlMWx0eWp1RkhBbWEzMGpCWVBEVDVuY1piQ0gxVXNmekJwbU9US1ZKb2laMXV4ZzQ9IiwiNGYzZWMzY2JlMTFlMTRiY2ZiYjYyNjVhYmYwM2M0YTIxZDYwOThkNGFlZGJjMDZmYjY2OGMyZjYyY2M5M2VmOCI6Ik1GRXdEUVlKWUlaSUFXVURCQUlDQlFBRVFEeFJPWFFCV2ZxWjVYdnhlOWRtUlwvWk40akgrNm90eENxWWY3aFcrcDRaN2VVSFhuUytIbDR4MkZibmtFc2xPZDZ0SHRWTGsrRWNvZnBUUWxPNFRad2s9In19LCJjb250ZW50X3NuYXBzaG90IjoiZXlKd2RXSnNhV05mYTJWNUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFUVktOMU00VEhCS1pETnZTbEJqWEM5bE5HUkxaMHg0U0hCSWRIRnNZM1JhVTFoTlVITkxhVXBDVlhGclBTSXNJbWxrWlc1MGFYUjVJam9pT0dVeFlUZzFZVEEwWVRKbFpqWXlZV016T1RCa05qSmhZVGxqTkRjNE5EaG1OV0l3WXpjMFkyVmxPV0ptT0RZM01XUTVNamxqWXpVNE5UUmxNR0UwWVNJc0ltbGtaVzUwYVhSNVgzUjVjR1VpT2lKcFpHVnVkR2wwZVY5allYSmtYMmxrSWl3aWMyTnZjR1VpT2lKaGNIQnNhV05oZEdsdmJpSXNJbWx1Wm04aU9uc2laR1YyYVdObFgyNWhiV1VpT2lKUGJHVnJjMkZ1WkhMaWdKbHpJRTFoWTBKdmIyc2dVSEp2SWl3aVpHVjJhV05sSWpvaWFWQm9iMjVsSW4xOSIsImlkIjoiMzBmYmVhZWUzZDgyZjM0NjA5NmZhOTliZTAxMzlmNmRiM2U0NzIxZjViNWM5ZWVlNTE0NmUwYTM0ODk4ODVkOSJ9")!
        
        let otCard = VSSCard(data: "eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTI4VDEzOjIzOjI5KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI4ZTFhODVhMDRhMmVmNjJhYzM5MGQ2MmFhOWM0Nzg0OGY1YjBjNzRjZWU5YmY4NjcxZDkyOWNjNTg1NGUwYTRhIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUU5paGVLTllNR2hKTnMzYzA1ekhuVTBHXC9BMldwY1JqNjNsSm0rVnE5a0lUZXNuSnFrSG04QUM4VW9uc1RZQjJBeHVVYVJaRGNvSjlNenJ2a2o5d0hBbz0iLCI0ZjNlYzNjYmUxMWUxNGJjZmJiNjI2NWFiZjAzYzRhMjFkNjA5OGQ0YWVkYmMwNmZiNjY4YzJmNjJjYzkzZWY4IjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUU5nUGJ3b01DMnRkZkwwXC9hVHZpRmQ3aExiODhoWjVWY1V3Znk2QW9cL09Jamtxc2JySnZ0Tk9EVlRmYnFxQ1BxNXJpaXpsSloxUWxMZCtBQmFQZTFIZzQ9In19LCJjb250ZW50X3NuYXBzaG90IjoiZXlKd2RXSnNhV05mYTJWNUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXcGxVbVpsTjJreGVUUlpVR3B5UkRkMWMzY3lTek5TYTFGRFJpdE9WMnQxTTBWV05sQnBPSHB1WTFrOUlpd2lhV1JsYm5ScGRIa2lPaUk0WlRGaE9EVmhNRFJoTW1WbU5qSmhZek01TUdRMk1tRmhPV00wTnpnME9HWTFZakJqTnpSalpXVTVZbVk0TmpjeFpEa3lPV05qTlRnMU5HVXdZVFJoSWl3aWFXUmxiblJwZEhsZmRIbHdaU0k2SW1sa1pXNTBhWFI1WDJOaGNtUmZhV1FpTENKelkyOXdaU0k2SW1Gd2NHeHBZMkYwYVc5dUlpd2lhVzVtYnlJNmV5SmtaWFpwWTJWZmJtRnRaU0k2SWs5c1pXdHpZVzVrY3VLQW1YTWdUV0ZqUW05dmF5QlFjbThpTENKa1pYWnBZMlVpT2lKcFVHaHZibVVpZlgwPSIsImlkIjoiZDBhZWQzNjdhN2M0ZmE4ZWRhZDBkNjE3ZmU2MDAxNjNjNDMzMTZmOTI5ZTRhMDFlZjExMTBkOTkxYmM0MDA2ZSJ9")!
        
        let recipientCardsSet = RecipientCardsSet(longTermCard: ltCard, oneTimeCard: otCard)
          
        let session = try! self.sessionManager.initializeInitiatorSession(withRecipientWithCard: self.card, recipientCardsSet: recipientCardsSet, additionalData: nil)
        
        let _ = try! self.keyStorageManager.getSessionKeys(forSessionWithId: session.identifier)
        
        let eps = 0.5
        
        XCTAssert(session.additionalData.count > 0)
        XCTAssert(session.decryptionKey.count > 0)
        XCTAssert(session.encryptionKey.count > 0)
        let now = Date()
        let expUpperBound = now.addingTimeInterval(self.sessionTtl)
        let expLowerBound = now.addingTimeInterval(self.sessionTtl - eps)
        XCTAssert(session.expirationDate > expLowerBound)
        XCTAssert(session.expirationDate < expUpperBound)
        XCTAssert(!session.isExpired(now: Date()))
        XCTAssert(session.identifier.count > 0)
        
        let activeSession = self.sessionManager.activeSession(withParticipantWithCardId: self.card.identifier)!
        
        XCTAssert(activeSession == session)
        
        let loadedSession = try! self.sessionManager.loadSession(recipientCardId: self.card.identifier, sessionId: session.identifier)
        
        XCTAssert(loadedSession == session)
        
        try! self.sessionManager.removeSessions(withParticipantWithCardId: self.card.identifier)
        
        XCTAssert(self.sessionManager.activeSession(withParticipantWithCardId: self.card.identifier) == nil)
        
        var errorWasThrown = false
        do {
            let _ = try self.sessionManager.loadSession(recipientCardId: self.card.identifier, sessionId: session.identifier)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
    }
    
    private func generateResponderSession(cardId: String, otKeyName: String = UUID().uuidString) throws -> SecureSession {
        let privateKey = self.crypto.generateKeyPair().privateKey
        let idEntry = CardEntry(identifier: cardId, publicKeyData: self.crypto.export(self.crypto.extractPublicKey(from: privateKey)))
        
        let ltKeyName = UUID().uuidString
        
        try! self.keyStorageManager.saveKeys(otKeys: [KeyStorageManager.HelperKeyEntry(privateKey: self.crypto.generateKeyPair().privateKey, name: otKeyName)], ltKey: KeyStorageManager.HelperKeyEntry(privateKey: self.crypto.generateKeyPair().privateKey, name: ltKeyName))
        
        let ephPublicKey = self.crypto.export(self.crypto.generateKeyPair().publicKey)
        let ephPublicKeySignature = try self.crypto.generateSignature(for: ephPublicKey, with: privateKey)
        
        var cipherText = Data(count: 16)
        cipherText.withUnsafeMutableBytes({
        NSUUID().getBytes($0)
        })
        var salt = Data(count: 16)
        salt.withUnsafeMutableBytes({
        NSUUID().getBytes($0)
        })
        
        let initiationMessage = InitiationMessage(initiatorIcId: idEntry.identifier, responderIcId: UUID().uuidString, responderLtcId: ltKeyName, responderOtcId: otKeyName, ephPublicKey: ephPublicKey, ephPublicKeySignature: ephPublicKeySignature, salt: salt, cipherText: cipherText)
        
        let session = try self.sessionManager.initializeResponderSession(initiatorCardEntry: idEntry, initiationMessage: initiationMessage, additionalData: nil)
        
        return session
    }
    
    func test002_InitializeResponder() {
        let cardId = UUID().uuidString
        let otKeyName = UUID().uuidString
        let session = try! self.generateResponderSession(cardId: cardId, otKeyName: otKeyName)
        
        var errorWasThrown = false
        do {
            let _ = try self.keyStorageManager.getOtPrivateKey(withName: otKeyName)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
        
        let _ = try! self.keyStorageManager.getSessionKeys(forSessionWithId: session.identifier)
        
        XCTAssert(session.additionalData.count > 0)
        XCTAssert(session.decryptionKey.count > 0)
        XCTAssert(session.encryptionKey.count > 0)
        let now = Date()
        let eps = 0.5
        let expUpperBound = now.addingTimeInterval(self.sessionTtl)
        let expLowerBound = now.addingTimeInterval(self.sessionTtl - eps)
        XCTAssert(session.expirationDate > expLowerBound)
        XCTAssert(session.expirationDate < expUpperBound)
        XCTAssert(!session.isExpired(now: Date()))
        XCTAssert(session.identifier.count > 0)
        
        let activeSession = self.sessionManager.activeSession(withParticipantWithCardId: cardId)!
        
        XCTAssert(activeSession == session)
        
        let loadedSession = try! self.sessionManager.loadSession(recipientCardId: cardId, sessionId: session.identifier)
        
        XCTAssert(loadedSession == session)
        
        try! self.sessionManager.removeSessions(withParticipantWithCardId: cardId)
        
        XCTAssert(self.sessionManager.activeSession(withParticipantWithCardId: cardId) == nil)
        
        errorWasThrown = false
        do {
            let _ = try self.sessionManager.loadSession(recipientCardId: cardId, sessionId: session.identifier)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
    }
    
    func test003_ActiveSessionChange() {
        let cardId = UUID().uuidString
        
        let session1 = try! self.generateResponderSession(cardId: cardId)
        let session2 = try! self.generateResponderSession(cardId: cardId)
        let session3 = try! self.generateResponderSession(cardId: cardId)
        
        let _ = try! self.keyStorageManager.getSessionKeys(forSessionWithId: session1.identifier)
        let _ = try! self.keyStorageManager.getSessionKeys(forSessionWithId: session2.identifier)
        let _ = try! self.keyStorageManager.getSessionKeys(forSessionWithId: session3.identifier)
        
        let activeSession = self.sessionManager.activeSession(withParticipantWithCardId: cardId)!
        
        XCTAssert(activeSession == session3)
        
        let loadedSession1 = try! self.sessionManager.loadSession(recipientCardId: cardId, sessionId: session1.identifier)
        let loadedSession2 = try! self.sessionManager.loadSession(recipientCardId: cardId, sessionId: session2.identifier)
        let loadedSession3 = try! self.sessionManager.loadSession(recipientCardId: cardId, sessionId: session3.identifier)
        
        XCTAssert(loadedSession1 == session1)
        XCTAssert(loadedSession2 == session2)
        XCTAssert(loadedSession3 == session3)
        
        try! self.sessionManager.removeSession(withParticipantWithCardId: cardId, sessionId: session3.identifier)
        
        let loadedSession21 = try! self.sessionManager.loadSession(recipientCardId: cardId, sessionId: session1.identifier)
        let loadedSession22 = try! self.sessionManager.loadSession(recipientCardId: cardId, sessionId: session2.identifier)
        
        XCTAssert(loadedSession21 == session1)
        XCTAssert(loadedSession22 == session2)
        
        var errorWasThrown = false
        do {
            let _ = try self.sessionManager.loadSession(recipientCardId: cardId, sessionId: session3.identifier)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
        
        let activeSession2 = self.sessionManager.activeSession(withParticipantWithCardId: cardId)!
        XCTAssert(activeSession2 == session2)
    }
    
    func test004_GentleReset() {
        let cardId1 = UUID().uuidString
        let cardId2 = UUID().uuidString
        
        let session11 = try! self.generateResponderSession(cardId: cardId1)
        let session12 = try! self.generateResponderSession(cardId: cardId1)
        let session21 = try! self.generateResponderSession(cardId: cardId2)
        
        let _ = try! self.keyStorageManager.getSessionKeys(forSessionWithId: session11.identifier)
        let _ = try! self.keyStorageManager.getSessionKeys(forSessionWithId: session12.identifier)
        let _ = try! self.keyStorageManager.getSessionKeys(forSessionWithId: session21.identifier)
        
        try! self.sessionManager.gentleReset()
        
        XCTAssert(self.sessionManager.activeSession(withParticipantWithCardId: cardId1) == nil)
        XCTAssert(self.sessionManager.activeSession(withParticipantWithCardId: cardId2) == nil)
        
        var errorWasThrown = false
        do {
            let _ = try self.sessionManager.loadSession(recipientCardId: cardId1, sessionId: session11.identifier)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
        
        errorWasThrown = false
        do {
            let _ = try self.sessionManager.loadSession(recipientCardId: cardId1, sessionId: session12.identifier)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
        
        errorWasThrown = false
        do {
            let _ = try self.sessionManager.loadSession(recipientCardId: cardId2, sessionId: session21.identifier)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
        
        errorWasThrown = false
        do {
            let _ = try self.keyStorageManager.getSessionKeys(forSessionWithId: session11.identifier)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
        
        errorWasThrown = false
        do {
            let _ = try self.keyStorageManager.getSessionKeys(forSessionWithId: session12.identifier)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
        
        errorWasThrown = false
        do {
            let _ = try self.keyStorageManager.getSessionKeys(forSessionWithId: session21.identifier)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
    }
    
    func test005_InitializeResponderInvalidEphKeySignature() {
        let cardId = UUID().uuidString
        let otKeyName = UUID().uuidString
        let privateKey = self.crypto.generateKeyPair().privateKey
        let idEntry = CardEntry(identifier: cardId, publicKeyData: self.crypto.export(self.crypto.extractPublicKey(from: privateKey)))
        
        let ltKeyName = UUID().uuidString
        
        try! self.keyStorageManager.saveKeys(otKeys: [KeyStorageManager.HelperKeyEntry(privateKey: self.crypto.generateKeyPair().privateKey, name: otKeyName)], ltKey: KeyStorageManager.HelperKeyEntry(privateKey: self.crypto.generateKeyPair().privateKey, name: ltKeyName))
        
        let ephPublicKey = self.crypto.export(self.crypto.generateKeyPair().publicKey)
        let ephPublicKeySignature = try! self.crypto.generateSignature(for: ephPublicKey, with: self.crypto.generateKeyPair().privateKey)
        
        var cipherText = Data(count: 16)
        cipherText.withUnsafeMutableBytes({
            NSUUID().getBytes($0)
        })
        var salt = Data(count: 16)
        salt.withUnsafeMutableBytes({
            NSUUID().getBytes($0)
        })
        
        let initiationMessage = InitiationMessage(initiatorIcId: idEntry.identifier, responderIcId: UUID().uuidString, responderLtcId: ltKeyName, responderOtcId: otKeyName, ephPublicKey: ephPublicKey, ephPublicKeySignature: ephPublicKeySignature, salt: salt, cipherText: cipherText)
        
        var errorWasThrown = false
        do {
            let _ = try self.sessionManager.initializeResponderSession(initiatorCardEntry: idEntry, initiationMessage: initiationMessage, additionalData: nil)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
    }
    
    func test006_InitializeInitiatorWrongOtCardSignature() {
        let ltCard = VSSCard( data:"eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTI4VDEzOjIzOjI5KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI4ZTFhODVhMDRhMmVmNjJhYzM5MGQ2MmFhOWM0Nzg0OGY1YjBjNzRjZWU5YmY4NjcxZDkyOWNjNTg1NGUwYTRhIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUU1jZWhpXC9ZVXFvZlpVbGdJVmdaRjgzc2ZcL2tObzNNZ0wzQlRmNDVlMWx0eWp1RkhBbWEzMGpCWVBEVDVuY1piQ0gxVXNmekJwbU9US1ZKb2laMXV4ZzQ9IiwiNGYzZWMzY2JlMTFlMTRiY2ZiYjYyNjVhYmYwM2M0YTIxZDYwOThkNGFlZGJjMDZmYjY2OGMyZjYyY2M5M2VmOCI6Ik1GRXdEUVlKWUlaSUFXVURCQUlDQlFBRVFEeFJPWFFCV2ZxWjVYdnhlOWRtUlwvWk40akgrNm90eENxWWY3aFcrcDRaN2VVSFhuUytIbDR4MkZibmtFc2xPZDZ0SHRWTGsrRWNvZnBUUWxPNFRad2s9In19LCJjb250ZW50X3NuYXBzaG90IjoiZXlKd2RXSnNhV05mYTJWNUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFUVktOMU00VEhCS1pETnZTbEJqWEM5bE5HUkxaMHg0U0hCSWRIRnNZM1JhVTFoTlVITkxhVXBDVlhGclBTSXNJbWxrWlc1MGFYUjVJam9pT0dVeFlUZzFZVEEwWVRKbFpqWXlZV016T1RCa05qSmhZVGxqTkRjNE5EaG1OV0l3WXpjMFkyVmxPV0ptT0RZM01XUTVNamxqWXpVNE5UUmxNR0UwWVNJc0ltbGtaVzUwYVhSNVgzUjVjR1VpT2lKcFpHVnVkR2wwZVY5allYSmtYMmxrSWl3aWMyTnZjR1VpT2lKaGNIQnNhV05oZEdsdmJpSXNJbWx1Wm04aU9uc2laR1YyYVdObFgyNWhiV1VpT2lKUGJHVnJjMkZ1WkhMaWdKbHpJRTFoWTBKdmIyc2dVSEp2SWl3aVpHVjJhV05sSWpvaWFWQm9iMjVsSW4xOSIsImlkIjoiMzBmYmVhZWUzZDgyZjM0NjA5NmZhOTliZTAxMzlmNmRiM2U0NzIxZjViNWM5ZWVlNTE0NmUwYTM0ODk4ODVkOSJ9")!
        
        let otCard = VSSCard(data: "eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTI4VDEzOjIzOjI5KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI4ZTFhODVhMDRhMmVmNjJhYzM5MGQ2MmFhOWM0Nzg0OGY1YjBjNzRjZWU5YmY4NjcxZDkyOWNjNTg1NGUwYTRhIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUUJwVmlWYmhRRDhKbVZUT1JndGsrWHM0ajVqSG13RW1uM1RpL1ZPUC9YWU80WDRFdlpneTlyVWFxZ0trYm8xb1RBUUcvaTBsNHpjM1dyN3QzRUM5OUE0PSIsIjRmM2VjM2NiZTExZTE0YmNmYmI2MjY1YWJmMDNjNGEyMWQ2MDk4ZDRhZWRiYzA2ZmI2NjhjMmY2MmNjOTNlZjgiOiJNRkV3RFFZSllJWklBV1VEQkFJQ0JRQUVRTmdQYndvTUMydGRmTDBcL2FUdmlGZDdoTGI4OGhaNVZjVXdmeTZBb1wvT0lqa3FzYnJKdnROT0RWVGZicXFDUHE1cmlpemxKWjFRbExkK0FCYVBlMUhnND0ifX0sImNvbnRlbnRfc25hcHNob3QiOiJleUp3ZFdKc2FXTmZhMlY1SWpvaVRVTnZkMEpSV1VSTE1sWjNRWGxGUVdwbFVtWmxOMmt4ZVRSWlVHcHlSRGQxYzNjeVN6TlNhMUZEUml0T1YydDFNMFZXTmxCcE9IcHVZMWs5SWl3aWFXUmxiblJwZEhraU9pSTRaVEZoT0RWaE1EUmhNbVZtTmpKaFl6TTVNR1EyTW1GaE9XTTBOemcwT0dZMVlqQmpOelJqWldVNVltWTROamN4WkRreU9XTmpOVGcxTkdVd1lUUmhJaXdpYVdSbGJuUnBkSGxmZEhsd1pTSTZJbWxrWlc1MGFYUjVYMk5oY21SZmFXUWlMQ0p6WTI5d1pTSTZJbUZ3Y0d4cFkyRjBhVzl1SWl3aWFXNW1ieUk2ZXlKa1pYWnBZMlZmYm1GdFpTSTZJazlzWld0ellXNWtjdUtBbVhNZ1RXRmpRbTl2YXlCUWNtOGlMQ0prWlhacFkyVWlPaUpwVUdodmJtVWlmWDA9IiwiaWQiOiJkMGFlZDM2N2E3YzRmYThlZGFkMGQ2MTdmZTYwMDE2M2M0MzMxNmY5MjllNGEwMWVmMTExMGQ5OTFiYzQwMDZlIn0=")!
        
        let recipientCardsSet = RecipientCardsSet(longTermCard: ltCard, oneTimeCard: otCard)
        
        var errorWasThrown = false
        do {
            let _ = try self.sessionManager.initializeInitiatorSession(withRecipientWithCard: self.card, recipientCardsSet: recipientCardsSet, additionalData: nil)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
    }
    
    func test007_InitializeInitiatorWrongLtCardSignature() {
        let ltCard = VSSCard( data:"eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTI4VDEzOjIzOjI5KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI4ZTFhODVhMDRhMmVmNjJhYzM5MGQ2MmFhOWM0Nzg0OGY1YjBjNzRjZWU5YmY4NjcxZDkyOWNjNTg1NGUwYTRhIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUUt5WS9wTnVWNkNacXhOd3NQQ0kzT0J6SXlCYld5TmpTWENVUDdpM2ltT1hhbXF2aGxLb2xUMW8vMm8xODIxYlE1TXlFeW5uSHVCVWMvWERQVk1IV2dBPSIsIjRmM2VjM2NiZTExZTE0YmNmYmI2MjY1YWJmMDNjNGEyMWQ2MDk4ZDRhZWRiYzA2ZmI2NjhjMmY2MmNjOTNlZjgiOiJNRkV3RFFZSllJWklBV1VEQkFJQ0JRQUVRRHhST1hRQldmcVo1WHZ4ZTlkbVJcL1pONGpIKzZvdHhDcVlmN2hXK3A0WjdlVUhYblMrSGw0eDJGYm5rRXNsT2Q2dEh0VkxrK0Vjb2ZwVFFsTzRUWndrPSJ9fSwiY29udGVudF9zbmFwc2hvdCI6ImV5SndkV0pzYVdOZmEyVjVJam9pVFVOdmQwSlJXVVJMTWxaM1FYbEZRVFZLTjFNNFRIQktaRE52U2xCalhDOWxOR1JMWjB4NFNIQklkSEZzWTNSYVUxaE5VSE5MYVVwQ1ZYRnJQU0lzSW1sa1pXNTBhWFI1SWpvaU9HVXhZVGcxWVRBMFlUSmxaall5WVdNek9UQmtOakpoWVRsak5EYzRORGhtTldJd1l6YzBZMlZsT1dKbU9EWTNNV1E1TWpsall6VTROVFJsTUdFMFlTSXNJbWxrWlc1MGFYUjVYM1I1Y0dVaU9pSnBaR1Z1ZEdsMGVWOWpZWEprWDJsa0lpd2ljMk52Y0dVaU9pSmhjSEJzYVdOaGRHbHZiaUlzSW1sdVptOGlPbnNpWkdWMmFXTmxYMjVoYldVaU9pSlBiR1ZyYzJGdVpITGlnSmx6SUUxaFkwSnZiMnNnVUhKdklpd2laR1YyYVdObElqb2lhVkJvYjI1bEluMTkiLCJpZCI6IjMwZmJlYWVlM2Q4MmYzNDYwOTZmYTk5YmUwMTM5ZjZkYjNlNDcyMWY1YjVjOWVlZTUxNDZlMGEzNDg5ODg1ZDkifQ==")!
        
        let otCard = VSSCard(data: "eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTI4VDEzOjIzOjI5KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI4ZTFhODVhMDRhMmVmNjJhYzM5MGQ2MmFhOWM0Nzg0OGY1YjBjNzRjZWU5YmY4NjcxZDkyOWNjNTg1NGUwYTRhIjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUU5paGVLTllNR2hKTnMzYzA1ekhuVTBHXC9BMldwY1JqNjNsSm0rVnE5a0lUZXNuSnFrSG04QUM4VW9uc1RZQjJBeHVVYVJaRGNvSjlNenJ2a2o5d0hBbz0iLCI0ZjNlYzNjYmUxMWUxNGJjZmJiNjI2NWFiZjAzYzRhMjFkNjA5OGQ0YWVkYmMwNmZiNjY4YzJmNjJjYzkzZWY4IjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUU5nUGJ3b01DMnRkZkwwXC9hVHZpRmQ3aExiODhoWjVWY1V3Znk2QW9cL09Jamtxc2JySnZ0Tk9EVlRmYnFxQ1BxNXJpaXpsSloxUWxMZCtBQmFQZTFIZzQ9In19LCJjb250ZW50X3NuYXBzaG90IjoiZXlKd2RXSnNhV05mYTJWNUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXcGxVbVpsTjJreGVUUlpVR3B5UkRkMWMzY3lTek5TYTFGRFJpdE9WMnQxTTBWV05sQnBPSHB1WTFrOUlpd2lhV1JsYm5ScGRIa2lPaUk0WlRGaE9EVmhNRFJoTW1WbU5qSmhZek01TUdRMk1tRmhPV00wTnpnME9HWTFZakJqTnpSalpXVTVZbVk0TmpjeFpEa3lPV05qTlRnMU5HVXdZVFJoSWl3aWFXUmxiblJwZEhsZmRIbHdaU0k2SW1sa1pXNTBhWFI1WDJOaGNtUmZhV1FpTENKelkyOXdaU0k2SW1Gd2NHeHBZMkYwYVc5dUlpd2lhVzVtYnlJNmV5SmtaWFpwWTJWZmJtRnRaU0k2SWs5c1pXdHpZVzVrY3VLQW1YTWdUV0ZqUW05dmF5QlFjbThpTENKa1pYWnBZMlVpT2lKcFVHaHZibVVpZlgwPSIsImlkIjoiZDBhZWQzNjdhN2M0ZmE4ZWRhZDBkNjE3ZmU2MDAxNjNjNDMzMTZmOTI5ZTRhMDFlZjExMTBkOTkxYmM0MDA2ZSJ9")!
        
        let recipientCardsSet = RecipientCardsSet(longTermCard: ltCard, oneTimeCard: otCard)
        
        var errorWasThrown = false
        do {
            let _ = try self.sessionManager.initializeInitiatorSession(withRecipientWithCard: self.card, recipientCardsSet: recipientCardsSet, additionalData: nil)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
    }
}

