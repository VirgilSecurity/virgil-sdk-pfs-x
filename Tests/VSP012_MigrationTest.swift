//
//  VSP012_MigrationTest.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/31/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
@testable import VirgilSDKPFS
import XCTest

class VSP012_MigrationTest: XCTestCase {
    private var secureChat: SecureChat!
    private var card: VSSCard!
    private var storage: InsensitiveDataStorage!
    private var crypto: VSSCryptoProtocol!
    private var privateKey: VSSPrivateKey!
    private var keyStorage: KeyStorageAdapter!
    
    override func setUp() {
        let cardStr = "eyJtZXRhIjp7InJlbGF0aW9ucyI6e30sImNyZWF0ZWRfYXQiOiIyMDE3LTA4LTMxVDE3OjAwOjM0KzAzMDAiLCJjYXJkX3ZlcnNpb24iOiI0LjAiLCJzaWducyI6eyI0MzIwYzk1ZGQ0YjBhYWJkOGVhNzNiMzAzZDRjM2FhMGRiNTAzMDY5YjBlNWI2N2U3ZDQ1YmRmNTRiMmI2M2Y3IjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUUZySGJvYThRZDJLZVlPd2pNOGlmWVphNk93SDAyNWVPeVRcLzFMT0pESEd1aHpvSW8wSFBKNzZyc2laeENTbGxzWExuYUZQYmd1Q0pmQnR5MzRhQkR3TT0iLCJhNjY2MzE4MDcxMjc0YWRiNzM4YWYzZjY3YjhjN2VjMjlkOTU0ZGUyY2FiZmQ3MWE5NDJlNmVhMzhlNTlmZmY5IjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUU5HNVZ4MThpRldyZTVVZlwvYjl4OGhackt6dENKVkxDTEVualdQbmtqTU5acHRMYlViRCtBSStkV0JMSGxBZFVmQm0zVEVJTUVJTW1vcXZTYnpZOHV3WT0iLCJlNjgwYmVmODdiYTc1ZDMzMWIwYTAyYmZhNmEyMGYwMmViNWM1YmE5YmM5NmZjNjFjYTU5NTQwNGIxMDAyNmY0IjoiTUZFd0RRWUpZSVpJQVdVREJBSUNCUUFFUU1zNDlFSklKYlhiVk0xSFoxazMrTkxMUnBlXC9xZVk2Q2QzZnRvWjJlbzRRTjV6OHo3R1BCXC9YQmFaMVA4azJhMk1jc3dwczFwYnJjdDhxZXltS0M5ZzQ9In19LCJjb250ZW50X3NuYXBzaG90IjoiZXlKd2RXSnNhV05mYTJWNUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFYRkdlblZMV1VNMk5GTlZha1ZjTDI5NlZVaGhaMjVzTkRSTE4zcDNVMVpQTVhaelJtUjNVM0U0UVRSTlBTSXNJbWxrWlc1MGFYUjVJam9pTkRsQ01rTXdRekl0UXpVNU1DMDBOVFkzTFVFd01EUXRNelUwTURNMU5USkZNMFJDSWl3aWFXUmxiblJwZEhsZmRIbHdaU0k2SW5SbGMzUWlMQ0p6WTI5d1pTSTZJbUZ3Y0d4cFkyRjBhVzl1SW4wPSIsImlkIjoiNDMyMGM5NWRkNGIwYWFiZDhlYTczYjMwM2Q0YzNhYTBkYjUwMzA2OWIwZTViNjdlN2Q0NWJkZjU0YjJiNjNmNyJ9"
        let cardData = Data(base64Encoded: cardStr)!
        self.card = VSSCard(data: cardStr)!
        
        var dict = try! JSONSerialization.jsonObject(with: cardData, options: []) as! [String : Any]
        
        // replace card id to have new one each time
        dict["id"] = UUID().uuidString
        
        let newData = try! JSONSerialization.data(withJSONObject: dict, options: [])
        let newCard = VSSCard(data: newData.base64EncodedString())!
        
        let consts = VSPTestsConst()
        self.crypto = VSSCrypto()
        
        let privateKeyData = Data(base64Encoded: "MC4CAQAwBQYDK2VwBCIEIBE0wJrCNI8eiwo/o4tiWFxx90zkGKNERkyej27+LcfK")!
        self.privateKey = crypto.importPrivateKey(from: privateKeyData)!
        
        let bundle = Bundle(for: VSP012_MigrationTest.self)
        let keystoragePath = bundle.path(forResource: "OLDKEYSTORAGE", ofType: "plist")!
        let data = FileManager().contents(atPath: keystoragePath)!
        
        self.keyStorage = KeyStorageAdapter(keyStorageMock: KeyStorageMock(name: UUID().uuidString, data: data))
        
        let preferences = try! SecureChatPreferences(crypto: self.crypto, identityPrivateKey: self.privateKey, identityCard: newCard, pfsUrl: consts.pfsServiceURL, accessToken: consts.applicationToken)
        preferences.keyStorage = self.keyStorage
        self.storage = preferences.insensitiveDataStorage
        
        self.secureChat = SecureChat(preferences: preferences)
    }
    
    func test001_CheckVersion() {
        XCTAssert(self.secureChat.getPreviousVersion() == .v1_0)
        XCTAssert(SecureChat.Version.currentVersion == .v1_1)
        
        try! self.secureChat.initialize(migrateAutomatically: false)
        
        XCTAssert(self.secureChat.getPreviousVersion() == .v1_0)
        
        try! self.secureChat.initialize(migrateAutomatically: true)
        
        XCTAssert(self.secureChat.getPreviousVersion() == .v1_1)
    }
    
    func test002_Migration() {
        let keyStorageManager = KeyStorageManager(crypto: self.crypto, keyStorage: self.keyStorage, identityCardId: self.card.identifier)

        let sessionInitializer = SessionInitializer(crypto: self.crypto, identityPrivateKey: self.privateKey, identityCard: self.card)
        let sessionStorageManager = SessionStorageManager(cardId: self.card.identifier, storage: self.storage)
        let sessionManager = SessionManager(identityCard: self.card, identityPrivateKey: self.privateKey, crypto: self.crypto, sessionTtl: 1000, keyStorageManager: keyStorageManager, sessionStorageManager: sessionStorageManager, sessionInitializer: sessionInitializer)
        
        let migration = try! MigrationV1_1(crypto: self.crypto, identityPrivateKey: self.privateKey, identityCard: self.card, keyStorage: self.keyStorage, keyStorageManager: keyStorageManager, storage: self.storage, sessionInitializer: sessionInitializer, sessionManager: sessionManager, defaultsClassType: UserDefaultsMock.self)
        
        try! migration.migrate()
    }
}
