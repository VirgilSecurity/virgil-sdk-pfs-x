//
//  VSP006_KeyStorageManagerTests.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/27/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCrypto
@testable import VirgilSDKPFS
import XCTest

class VSP006_KeyStorageManagerTests: XCTestCase {
    private var crypto: VSSCrypto!
    private var keyStorageManager: KeyStorageManager!
    
    override func setUp() {
        self.crypto = VSSCrypto()
        self.keyStorageManager = KeyStorageManager(crypto: self.crypto, keyStorage: KeychainKeyStorage(), identityCardId: UUID().uuidString)
    }
    
    override func tearDown() {
        
    }
    
    func test001_hasRelevantLtKey() {
        XCTAssert(!self.keyStorageManager.hasRelevantLtKey(longTermKeyTtl: 5))
        
        let ltPrivateKeyName = UUID().uuidString
        try! self.keyStorageManager.saveKeys(otKeys: [], ltKey: KeyStorageManager.HelperKeyEntry(privateKey: self.crypto.generateKeyPair().privateKey, name: ltPrivateKeyName))
        
        let _ = try! self.keyStorageManager.getLtPrivateKey(withName: ltPrivateKeyName)
        
        XCTAssert(self.keyStorageManager.hasRelevantLtKey(longTermKeyTtl: 5))
        
        XCTAssert(!self.keyStorageManager.hasRelevantLtKey(now: Date().addingTimeInterval(6), longTermKeyTtl: 5))
    }
    
    func test002_LtKeys() {
        let ltName1 = UUID().uuidString
        let ltName2 = UUID().uuidString
        
        try! self.keyStorageManager.saveKeys(otKeys: [], ltKey: KeyStorageManager.HelperKeyEntry(privateKey: self.crypto.generateKeyPair().privateKey, name: ltName1))
        
        let _ = try! self.keyStorageManager.getLtPrivateKey(withName: ltName1)
        
        XCTAssert(self.keyStorageManager.hasRelevantLtKey(longTermKeyTtl: 5))
        XCTAssert(!self.keyStorageManager.hasRelevantLtKey(now: Date().addingTimeInterval(6), longTermKeyTtl: 5))

        sleep(3)
        
        try! self.keyStorageManager.saveKeys(otKeys: [], ltKey: KeyStorageManager.HelperKeyEntry(privateKey: self.crypto.generateKeyPair().privateKey, name: ltName2))
        
        let _ = try! self.keyStorageManager.getLtPrivateKey(withName: ltName2)
        
        XCTAssert(self.keyStorageManager.hasRelevantLtKey(longTermKeyTtl: 5))
        XCTAssert(self.keyStorageManager.hasRelevantLtKey(now: Date().addingTimeInterval(1), longTermKeyTtl: 5))
        XCTAssert(!self.keyStorageManager.hasRelevantLtKey(now: Date().addingTimeInterval(6), longTermKeyTtl: 5))
        
        try! self.keyStorageManager.removeLtPrivateKeys(withNames: [ltName1])
        
        var errorWasThrown = false
        do {
            let _ = try self.keyStorageManager.getLtPrivateKey(withName: ltName1)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
        
        XCTAssert(self.keyStorageManager.hasRelevantLtKey(longTermKeyTtl: 5))
        XCTAssert(self.keyStorageManager.hasRelevantLtKey(now: Date().addingTimeInterval(1), longTermKeyTtl: 5))
        XCTAssert(!self.keyStorageManager.hasRelevantLtKey(now: Date().addingTimeInterval(6), longTermKeyTtl: 5))
        
        try! self.keyStorageManager.removeLtPrivateKeys(withNames: [ltName2])
        
        XCTAssert(!self.keyStorageManager.hasRelevantLtKey(longTermKeyTtl: 5))
        
        errorWasThrown = false
        do {
            let _ = try self.keyStorageManager.getLtPrivateKey(withName: ltName2)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
    }
    
    func test003_SessionKeys1() {
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
        
        let sessionKeys0 = KeyStorageManager.SessionKeys(encryptionKey: encryptionKey, decryptionKey: decryptionKey)
        try! self.keyStorageManager.saveSessionKeys(sessionKeys0, forSessionWithId: sessionId)
        
        let sessionKeys1 = try! self.keyStorageManager.getSessionKeys(forSessionWithId: sessionId)
        
        XCTAssert(sessionKeys1.encryptionKey == encryptionKey)
        XCTAssert(sessionKeys1.decryptionKey == decryptionKey)
        
        try! self.keyStorageManager.removeSessionKeys(forSessionWithId: sessionId)
        
        var errorWasThrown = false
        do {
            let _ = try self.keyStorageManager.getSessionKeys(forSessionWithId: sessionId)
        }
        catch {
            errorWasThrown = true
        }
        
        XCTAssert(errorWasThrown)
    }
    
    func test004_SessionKeys2() {
        var sessionId1 = Data(count: 16)
        sessionId1.withUnsafeMutableBytes({
            NSUUID().getBytes($0)
        })
        
        var sessionId2 = Data(count: 16)
        sessionId2.withUnsafeMutableBytes({
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
        
        let sessionKeys0 = KeyStorageManager.SessionKeys(encryptionKey: encryptionKey, decryptionKey: decryptionKey)
        try! self.keyStorageManager.saveSessionKeys(sessionKeys0, forSessionWithId: sessionId1)
        XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().session.count == 1)
        try! self.keyStorageManager.saveSessionKeys(sessionKeys0, forSessionWithId: sessionId2)
        XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().session.count == 2)
        
        let sessionKeys11 = try! self.keyStorageManager.getSessionKeys(forSessionWithId: sessionId1)
        let sessionKeys12 = try! self.keyStorageManager.getSessionKeys(forSessionWithId: sessionId1)
        
        XCTAssert(sessionKeys11.encryptionKey == encryptionKey)
        XCTAssert(sessionKeys11.decryptionKey == decryptionKey)
        XCTAssert(sessionKeys12.encryptionKey == encryptionKey)
        XCTAssert(sessionKeys12.decryptionKey == decryptionKey)
        
        try! self.keyStorageManager.removeSessionKeys(forSessionsWithIds: [sessionId1, sessionId2])
        XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().session.count == 0)
        
        var errorWasThrown = false
        do {
            let _ = try self.keyStorageManager.getSessionKeys(forSessionWithId: sessionId1)
        }
        catch {
            errorWasThrown = true
        }
        
        XCTAssert(errorWasThrown)
        
        errorWasThrown = false
        do {
            let _ = try self.keyStorageManager.getSessionKeys(forSessionWithId: sessionId2)
        }
        catch {
            errorWasThrown = true
        }
        
        XCTAssert(errorWasThrown)
    }

    func test005_OtKeys() {
        let keyEntry1 = KeyStorageManager.HelperKeyEntry(privateKey: self.crypto.generateKeyPair().privateKey, name: UUID().uuidString)
        let keyEntry2 = KeyStorageManager.HelperKeyEntry(privateKey: self.crypto.generateKeyPair().privateKey, name: UUID().uuidString)
        let keyEntry3 = KeyStorageManager.HelperKeyEntry(privateKey: self.crypto.generateKeyPair().privateKey, name: UUID().uuidString)
        
        
        try! self.keyStorageManager.saveKeys(otKeys: [keyEntry1, keyEntry2, keyEntry3], ltKey: nil)
        
        XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().ot.count == 3)
        
        let _ = try! self.keyStorageManager.getOtPrivateKey(withName: keyEntry1.name)
        let _ = try! self.keyStorageManager.getOtPrivateKey(withName: keyEntry2.name)
        let _ = try! self.keyStorageManager.getOtPrivateKey(withName: keyEntry3.name)
        
        try! self.keyStorageManager.removeOtPrivateKey(withName: keyEntry1.name)
        
        var errorWasThrown = false
        do {
            let _ = try self.keyStorageManager.getOtPrivateKey(withName: keyEntry1.name)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
        let _ = try! self.keyStorageManager.getOtPrivateKey(withName: keyEntry2.name)
        let _ = try! self.keyStorageManager.getOtPrivateKey(withName: keyEntry3.name)
        
        XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().ot.count == 2)
        
        try! self.keyStorageManager.removeOtPrivateKeys(withNames: [keyEntry2.name, keyEntry3.name])
        
        errorWasThrown = false
        do {
            let _ = try self.keyStorageManager.getOtPrivateKey(withName: keyEntry1.name)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
        errorWasThrown = false
        do {
            let _ = try self.keyStorageManager.getOtPrivateKey(withName: keyEntry2.name)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
        errorWasThrown = false
        do {
            let _ = try self.keyStorageManager.getOtPrivateKey(withName: keyEntry3.name)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
        
        XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().ot.count == 0)
    }
    
    func test006_gentleReset() {
        var sessionId1 = Data(count: 16)
        sessionId1.withUnsafeMutableBytes({
            NSUUID().getBytes($0)
        })
        
        var sessionId2 = Data(count: 16)
        sessionId2.withUnsafeMutableBytes({
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
        
        let sessionKeys0 = KeyStorageManager.SessionKeys(encryptionKey: encryptionKey, decryptionKey: decryptionKey)
        try! self.keyStorageManager.saveSessionKeys(sessionKeys0, forSessionWithId: sessionId1)
        XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().session.count == 1)
        try! self.keyStorageManager.saveSessionKeys(sessionKeys0, forSessionWithId: sessionId2)
        XCTAssert(try! self.keyStorageManager.getAllKeysAttrs().session.count == 2)
        
        let keyEntry1 = KeyStorageManager.HelperKeyEntry(privateKey: self.crypto.generateKeyPair().privateKey, name: UUID().uuidString)
        let keyEntry2 = KeyStorageManager.HelperKeyEntry(privateKey: self.crypto.generateKeyPair().privateKey, name: UUID().uuidString)
        let keyEntry3 = KeyStorageManager.HelperKeyEntry(privateKey: self.crypto.generateKeyPair().privateKey, name: UUID().uuidString)
        
        let ltKeyEntry = KeyStorageManager.HelperKeyEntry(privateKey: self.crypto.generateKeyPair().privateKey, name: UUID().uuidString)
        try! self.keyStorageManager.saveKeys(otKeys: [keyEntry1, keyEntry2, keyEntry3], ltKey: ltKeyEntry)
        
        self.keyStorageManager.gentleReset()
        
        let (r1, r2, r3) = try! self.keyStorageManager.getAllKeysAttrs()
        XCTAssert(r1.count == 0)
        XCTAssert(r2.count == 0)
        XCTAssert(r3.count == 0)
        
        var errorWasThrown = false
        
        errorWasThrown = false
        do {
            let _ = try self.keyStorageManager.getLtPrivateKey(withName: ltKeyEntry.name)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
        errorWasThrown = false
        do {
            let _ = try self.keyStorageManager.getOtPrivateKey(withName: keyEntry1.name)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
        errorWasThrown = false
        do {
            let _ = try self.keyStorageManager.getOtPrivateKey(withName: keyEntry2.name)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
        errorWasThrown = false
        do {
            let _ = try self.keyStorageManager.getOtPrivateKey(withName: keyEntry3.name)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
        errorWasThrown = false
        do {
            let _ = try self.keyStorageManager.getSessionKeys(forSessionWithId: sessionId1)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
        errorWasThrown = false
        do {
            let _ = try self.keyStorageManager.getSessionKeys(forSessionWithId: sessionId2)
        }
        catch {
            errorWasThrown = true
        }
        XCTAssert(errorWasThrown)
    }
}
