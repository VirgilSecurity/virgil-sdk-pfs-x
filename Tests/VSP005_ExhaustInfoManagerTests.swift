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
        
        XCTAssert(exhaustInfo.count == 0)
    }
    
    func test002_Save1Info() {
        let info = OtcExhaustInfo(cardId: UUID().uuidString, exhaustDate: Date())
        try! self.exhaustInfoManager.saveKeysExhaustInfo([info])
        
        let exhaustInfo = try! self.exhaustInfoManager.getKeysExhaustInfo()
        
        XCTAssert(exhaustInfo.count == 1)
        XCTAssert(exhaustInfo[0] == info)
    }
    
    func test002_Save2Info() {
        let info1 = OtcExhaustInfo(cardId: UUID().uuidString, exhaustDate: Date())
        let info2 = OtcExhaustInfo(cardId: UUID().uuidString, exhaustDate: Date().addingTimeInterval(5))
        try! self.exhaustInfoManager.saveKeysExhaustInfo([info1, info2])
        
        let exhaustInfo = try! self.exhaustInfoManager.getKeysExhaustInfo()
        
        XCTAssert(exhaustInfo.count == 2)
        XCTAssert(exhaustInfo[0] == info1)
        XCTAssert(exhaustInfo[1] == info2)
    }
}
