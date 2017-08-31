//
//  VSP005_ExhaustInfoManagerTests.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/27/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
@testable import VirgilSDKPFS
import XCTest

class VSP005_ExhaustInfoManagerTests: XCTestCase {
    private var exhaustInfoManager: ExhaustInfoManager!
    
    override func setUp() {
        let cardId = UUID().uuidString
        self.exhaustInfoManager = ExhaustInfoManager(cardId: cardId, storage: try! UserDefaultsDataStorage.makeStorage(forIdentifier: cardId))
    }
    
    override func tearDown() {
        
    }
    
    func test001_GetEmptyInfo() {
        let exhaustInfo = try! self.exhaustInfoManager.getKeysExhaustInfo()
        
        XCTAssert(exhaustInfo.otc.count == 0)
        XCTAssert(exhaustInfo.ltc.count == 0)
        XCTAssert(exhaustInfo.sessions.count == 0)
    }
    
    func test002_SaveInfo() {
        let otc = [
            ExhaustInfoEntry(identifier: UUID().uuidString, exhaustDate: Date()),
            ExhaustInfoEntry(identifier: UUID().uuidString, exhaustDate: Date())
        ]
        
        let ltc = [
            ExhaustInfoEntry(identifier: UUID().uuidString, exhaustDate: Date()),
            ExhaustInfoEntry(identifier: UUID().uuidString, exhaustDate: Date()),
            ExhaustInfoEntry(identifier: UUID().uuidString, exhaustDate: Date())
        ]
        
        var sessionId = Data(count: 16)
        sessionId.withUnsafeMutableBytes({
            NSUUID().getBytes($0)
        })
        
        let sessions = [
            SessionExhaustInfo(identifier: sessionId, cardId: UUID().uuidString, exhaustDate: Date())
        ]
        
        
        let info = ExhaustInfo(otc: otc, ltc: ltc, sessions: sessions)
        try! self.exhaustInfoManager.saveKeysExhaustInfo(info)
        
        let exhaustInfo = try! self.exhaustInfoManager.getKeysExhaustInfo()
        
        XCTAssert(exhaustInfo.otc == otc)
        XCTAssert(exhaustInfo.ltc == ltc)
        XCTAssert(exhaustInfo.sessions == sessions)
    }
}
