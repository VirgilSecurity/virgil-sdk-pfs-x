//
//  VSP004_SessionStorageManagerTests.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/25/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
@testable import VirgilSDKPFS
import XCTest

class VSP004_SessionStorageManagerTests: XCTestCase {
    private var sessionStorageManager: SessionStorageManager!
    private var cardId: String!
    private var recipientCardId1: String!
    private var recipientCardId2: String!
    private var sessionId1: Data!
    private var sessionId2: Data!
    private var sessionId3: Data!
    private var sessionId4: Data!
    private var sessionState1: SessionState!
    private var sessionState2: SessionState!
    private var sessionState3: SessionState!
    private var sessionState4: SessionState!
    
    override func setUp() {
        super.setUp()
        
        self.cardId = UUID().uuidString
        self.recipientCardId1 = UUID().uuidString
        self.recipientCardId2 = UUID().uuidString
        let storage = try! UserDefaultsDataStorage.makeStorage(forIdentifier: self.cardId)
        self.sessionStorageManager = SessionStorageManager(cardId: self.cardId, storage: storage)
        
        self.sessionId1 = Data(count: 16)
        self.sessionId1.withUnsafeMutableBytes({
            NSUUID().getBytes($0)
        })
        
        self.sessionId2 = Data(count: 16)
        self.sessionId2.withUnsafeMutableBytes({
            NSUUID().getBytes($0)
        })
        
        self.sessionId3 = Data(count: 16)
        self.sessionId3.withUnsafeMutableBytes({
            NSUUID().getBytes($0)
        })
        
        self.sessionId4 = Data(count: 16)
        self.sessionId4.withUnsafeMutableBytes({
            NSUUID().getBytes($0)
        })
        
        self.sessionState1 = SessionState(creationDate: Date(), expirationDate: Date(), sessionId: self.sessionId1, additionalData: Data())
        self.sessionState2 = SessionState(creationDate: Date().addingTimeInterval(5), expirationDate: Date(), sessionId: self.sessionId2, additionalData: Data())
        self.sessionState3 = SessionState(creationDate: Date(), expirationDate: Date(), sessionId: self.sessionId3, additionalData: Data())
        self.sessionState4 = SessionState(creationDate: Date(), expirationDate: Date(), sessionId: self.sessionId4, additionalData: Data())
        
        try! self.sessionStorageManager.addSessionState(self.sessionState1, forRecipientCardId: self.recipientCardId1)
        try! self.sessionStorageManager.addSessionState(self.sessionState2, forRecipientCardId: self.recipientCardId1)
        try! self.sessionStorageManager.addSessionState(self.sessionState3, forRecipientCardId: self.recipientCardId2)
        try! self.sessionStorageManager.addSessionState(self.sessionState4, forRecipientCardId: self.recipientCardId2)
    }
    
    override func tearDown() {
        self.sessionStorageManager = nil
        
        super.tearDown()
    }
    
    func test001_GetSession() {
        let sessionState = try! self.sessionStorageManager.getSessionState(forRecipientCardId: self.recipientCardId1, sessionId: self.sessionState1.sessionId)
        
        XCTAssert(sessionState! == self.sessionState1!)
    }
    
    func test002_GetNonExistentSession() {
        let sessionState = try! self.sessionStorageManager.getSessionState(forRecipientCardId: self.recipientCardId2, sessionId: self.sessionState1.sessionId)
        
        XCTAssert(sessionState == nil)
    }
    
    func test003_GetAllSessionsForRecipient() {
        let sessionStatesIds = try! self.sessionStorageManager.getSessionStatesIds(forRecipientCardId: self.recipientCardId1)
        
        var createdIds = Set<Data>()
        createdIds.insert(self.sessionState1.sessionId)
        createdIds.insert(self.sessionState2.sessionId)
        
        XCTAssert(sessionStatesIds.count == 2)
        XCTAssert(Set<Data>(sessionStatesIds) == createdIds)
    }
    
    func test004_GetAllSessions() {
        let sessionStates = try! self.sessionStorageManager.getAllSessionsStates()
        
        XCTAssert(sessionStates.count == 2)
        XCTAssert(sessionStates[self.recipientCardId1]!.count == 2)
        XCTAssert(sessionStates[self.recipientCardId2]!.count == 2)
    }
    
    func test005_GetNewestSessionState() {
        let sessionState = try! self.sessionStorageManager.getNewestSessionState(forRecipientCardId: self.recipientCardId1)
        
        XCTAssert(sessionState == self.sessionState2)
    }
    
    func test006_RemoveSessionState() {
        try! self.sessionStorageManager.removeSessionState(forCardId: self.recipientCardId1, sessionId: self.sessionState1.sessionId)
        
        let sessionState = try! self.sessionStorageManager.getSessionState(forRecipientCardId: self.recipientCardId1, sessionId: self.sessionState1.sessionId)
        
        XCTAssert(sessionState == nil)
    }
    
    func test006_RemoveSessionStates1() {
        try! self.sessionStorageManager.removeSessionsStates(dict: [
            self.recipientCardId1: nil
            ])
        
        let sessionState1 = try! self.sessionStorageManager.getSessionState(forRecipientCardId: self.recipientCardId1, sessionId: self.sessionState1.sessionId)
        let sessionState2 = try! self.sessionStorageManager.getSessionState(forRecipientCardId: self.recipientCardId1, sessionId: self.sessionState2.sessionId)
        
        try! self.sessionStorageManager.removeSessionsStates(dict: [
            self.recipientCardId2: [self.sessionState3.sessionId]
            ])
        
        let sessionState3 = try! self.sessionStorageManager.getSessionState(forRecipientCardId: self.recipientCardId2, sessionId: self.sessionState3.sessionId)
        let sessionState4 = try! self.sessionStorageManager.getSessionState(forRecipientCardId: self.recipientCardId2, sessionId: self.sessionState4.sessionId)
        
        XCTAssert(sessionState1 == nil)
        XCTAssert(sessionState2 == nil)
        XCTAssert(sessionState3 == nil)
        XCTAssert(sessionState4 == self.sessionState4)
    }
}
