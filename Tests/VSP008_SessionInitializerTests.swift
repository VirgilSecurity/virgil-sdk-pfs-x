//
//  VSP008_SessionInitializerTests.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/28/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import Foundation
@testable import VirgilSDKPFS
import XCTest

class VSP008_SessionInitializerTests: XCTestCase {
    private var crypto: VSSCryptoProtocol!
    private var sessionInitializer: SessionInitializer!
    
    override func setUp() {
        self.crypto = VSSCrypto()
        
        let card = VSSCard(data: "eyJpZCI6IjExOWU4ZGIxMjg0MGNkODllYjY3YzY4OGM0NTFiMTA4ZmYwZmQ1M2VmMThjNjZlZDQ1NWQ3NTcwODc5Njc1NWEiLCJjb250ZW50X3NuYXBzaG90IjoiZXlKcFpHVnVkR2wwZVNJNkltUmhabUZtYjNCdlFERXlhRzl6ZEdsdVp5NXVaWFFpTENKcFpHVnVkR2wwZVY5MGVYQmxJam9pWlcxaGFXd2lMQ0p3ZFdKc2FXTmZhMlY1SWpvaVRVTnZkMEpSV1VSTE1sWjNRWGxGUVdaVU0yaFdObmwwWEM5dVFtbDRkRU5wU2xkQmRXSjFPRTVFYzNadFRXUjRVR1Y2ZEZKcUswaExaV2gzUFNJc0luTmpiM0JsSWpvaVoyeHZZbUZzSW4wPSIsIm1ldGEiOnsic2lnbnMiOnsiMTE5ZThkYjEyODQwY2Q4OWViNjdjNjg4YzQ1MWIxMDhmZjBmZDUzZWYxOGM2NmVkNDU1ZDc1NzA4Nzk2NzU1YSI6Ik1GRXdEUVlKWUlaSUFXVURCQUlDQlFBRVFMVlg3QUVMUDN4NEl4dDJVOUNkSlFQUCtydk5aTjhtTGRsSlJmazlpOTlXdVZJcENoWWtua052Y0NSVnlMNUxtY2wvNEJlOHlKc1E1VFkvYUVwb1pBND0iLCI2N2I4ZWU4ZTUzYjRjMGM2YjY1YjRiYmRkYTZmYTE1OWU4MjA4ZjU4ZmZjMjkwZWM2MWE3MmMzZmQwN2FkMDM1IjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUUtrR1pSRnVBMSsrdzc1NTZtVFBNL2FRaUc1MjhlamQ5Y3d3NGtxTkU3d1BrTnZBOXFxV1hJbWIwdlNGb0w3cXM4VFBNMm5YS2ZBUkdHU3NaMXBQOXdrPSIsIjNlMjlkNDMzNzMzNDhjZmIzNzNiN2VhZTE4OTIxNGRjMDFkNzIzNzc2NWU1NzJkYjY4NTgzOWI2NGFkY2E4NTMiOiJNRkV3RFFZSllJWklBV1VEQkFJQ0JRQUVRSC9xbzdFeVI1WlEwZ0ZkV0RwRlZMS0hhUkZ6dkhUTit3SUpSR1pqZDhKbWFYbk8vYTJ6OVF4K2xvTVloZEFoQXg5QXpROVlkcnJDTzBOVldqd080QUU9In0sImNyZWF0ZWRfYXQiOiIyMDE3LTAzLTEzVDEzOjIwOjAwKzAyOjAwIiwiY2FyZF92ZXJzaW9uIjoiNC4wIn19")!
        
        self.sessionInitializer = SessionInitializer(crypto: self.crypto, identityPrivateKey: self.crypto.generateKeyPair().privateKey, identityCard: card)
    }
    
    func test001_InitializeInitiator() {
        let ephPrivateKey = self.crypto.generateKeyPair().privateKey
        let idEntry = CardEntry(identifier: UUID().uuidString, publicKeyData: self.crypto.export(self.crypto.generateKeyPair().publicKey))
        let ltEntry = CardEntry(identifier: UUID().uuidString, publicKeyData: self.crypto.export(self.crypto.generateKeyPair().publicKey))
        let otEntry = CardEntry(identifier: UUID().uuidString, publicKeyData: self.crypto.export(self.crypto.generateKeyPair().publicKey))
        
        var additionalData = Data(count: 16)
        additionalData.withUnsafeMutableBytes({
            NSUUID().getBytes($0)
        })
        
        let expirationDate = Date().addingTimeInterval(10)
        let session = try! self.sessionInitializer.initializeInitiatorSession(ephPrivateKey: ephPrivateKey, recipientIdCard: idEntry, recipientLtCard: ltEntry, recipientOtCard: otEntry, additionalData: additionalData, expirationDate: expirationDate)
        
        XCTAssert(session.additionalData.count > 0)
        XCTAssert(session.decryptionKey.count > 0)
        XCTAssert(session.encryptionKey.count > 0)
        XCTAssert(session.expirationDate == expirationDate)
        XCTAssert(session.isExpired == false)
        XCTAssert(session.sessionId.count > 0)
    }
    
    func test002_InitializeInitiatorWeak() {
        let ephPrivateKey = self.crypto.generateKeyPair().privateKey
        let idEntry = CardEntry(identifier: UUID().uuidString, publicKeyData: self.crypto.export(self.crypto.generateKeyPair().publicKey))
        let ltEntry = CardEntry(identifier: UUID().uuidString, publicKeyData: self.crypto.export(self.crypto.generateKeyPair().publicKey))
        let otEntry = CardEntry(identifier: UUID().uuidString, publicKeyData: self.crypto.export(self.crypto.generateKeyPair().publicKey))
        
        let expirationDate = Date().addingTimeInterval(10)
        let session = try! self.sessionInitializer.initializeInitiatorSession(ephPrivateKey: ephPrivateKey, recipientIdCard: idEntry, recipientLtCard: ltEntry, recipientOtCard: otEntry, additionalData: nil, expirationDate: expirationDate)
        
        XCTAssert(session.additionalData.count > 0)
        XCTAssert(session.decryptionKey.count > 0)
        XCTAssert(session.encryptionKey.count > 0)
        XCTAssert(session.expirationDate == expirationDate)
        XCTAssert(session.isExpired == false)
        XCTAssert(session.sessionId.count > 0)
    }
    
    func test003_InitializeResponder() {
        let idPrivateKey = self.crypto.generateKeyPair().privateKey
        let idEntry = CardEntry(identifier: UUID().uuidString, publicKeyData: self.crypto.export(self.crypto.extractPublicKey(from: idPrivateKey)))
        let privateKey = self.crypto.generateKeyPair().privateKey
        let ltKey = self.crypto.generateKeyPair().privateKey
        let ephPublicKey = self.crypto.export(self.crypto.generateKeyPair().publicKey)
        
        var additionalData = Data(count: 16)
        additionalData.withUnsafeMutableBytes({
            NSUUID().getBytes($0)
        })
        
        let expirationDate = Date().addingTimeInterval(10)
        let session = try! self.sessionInitializer.initializeResponderSession(initiatorCardEntry: idEntry, privateKey: privateKey, ltPrivateKey: ltKey, otPrivateKey: nil, ephPublicKey: ephPublicKey, additionalData: additionalData, expirationDate: expirationDate)
        
        XCTAssert(session.additionalData.count > 0)
        XCTAssert(session.decryptionKey.count > 0)
        XCTAssert(session.encryptionKey.count > 0)
        XCTAssert(session.expirationDate == expirationDate)
        XCTAssert(session.isExpired == false)
        XCTAssert(session.sessionId.count > 0)
    }
    
    func test004_InitializeResponderWeak() {
        let idPrivateKey = self.crypto.generateKeyPair().privateKey
        let idEntry = CardEntry(identifier: UUID().uuidString, publicKeyData: self.crypto.export(self.crypto.extractPublicKey(from: idPrivateKey)))
        let privateKey = self.crypto.generateKeyPair().privateKey
        let ltKey = self.crypto.generateKeyPair().privateKey
        let ephPublicKey = self.crypto.export(self.crypto.generateKeyPair().publicKey)
        
        let expirationDate = Date().addingTimeInterval(10)
        let session = try! self.sessionInitializer.initializeResponderSession(initiatorCardEntry: idEntry, privateKey: privateKey, ltPrivateKey: ltKey, otPrivateKey: nil, ephPublicKey: ephPublicKey, additionalData: nil, expirationDate: expirationDate)
        
        XCTAssert(session.additionalData.count > 0)
        XCTAssert(session.decryptionKey.count > 0)
        XCTAssert(session.encryptionKey.count > 0)
        XCTAssert(session.expirationDate == expirationDate)
        XCTAssert(session.isExpired == false)
        XCTAssert(session.sessionId.count > 0)
    }
    
    func test005_InitializeSaved() {
        var sessionId = Data(count: 16)
        sessionId.withUnsafeMutableBytes({
            NSUUID().getBytes($0)
        })
        var encryptionKey = Data(count: 16)
        encryptionKey.withUnsafeMutableBytes({
            NSUUID().getBytes($0)
        })
        var decryptionKey = Data(count: 16)
        decryptionKey.withUnsafeMutableBytes({
            NSUUID().getBytes($0)
        })
        var additionalData = Data(count: 16)
        additionalData.withUnsafeMutableBytes({
            NSUUID().getBytes($0)
        })
        let expirationDate = Date().addingTimeInterval(10)
        let session = try! self.sessionInitializer.initializeSavedSession(sessionId: sessionId, encryptionKey: encryptionKey, decryptionKey: decryptionKey, additionalData: additionalData, expirationDate: expirationDate)
        
        XCTAssert(session.additionalData == additionalData)
        XCTAssert(session.decryptionKey == decryptionKey)
        XCTAssert(session.encryptionKey == encryptionKey)
        XCTAssert(session.expirationDate == expirationDate)
        XCTAssert(session.isExpired == false)
        XCTAssert(session.sessionId == sessionId)
    }
}
