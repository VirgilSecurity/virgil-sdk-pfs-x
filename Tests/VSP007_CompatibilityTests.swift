//
//  VSP007_CompatibilityTests.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/28/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
@testable import VirgilSDKPFS
import XCTest

class VSP007_CompatibilityTests: XCTestCase {
    func test001_InitiationMessage() {
        let testFileURL = Bundle(for: type(of: self)).url(forResource: "InitiationMessageExample", withExtension: "txt")!
        let testFileData = try! Data(contentsOf: testFileURL)
        
        let initiationMessage = try! SecureSession.extractInitiationMessage(fromData: testFileData)
        
        XCTAssert(initiationMessage.responderIcId == "1d6dfd3624c9211071e78dc950c7a69f7dfcbccc404f69a08fc5fd791c1e299d")
        XCTAssert(initiationMessage.cipherText == Data(base64Encoded: "qQlrx2niPx+pQ+xCcPTnrih46ChEGp/XNQ5IaWa9bND+9UKpVw==")!)
        XCTAssert(initiationMessage.responderOtcId == "dd58dcccb4e521b71e9faa6d78371c57d1540fb9d1593f57fe75b14b0d66b47f")
        XCTAssert(initiationMessage.responderLtcId == "555eb3311d1a29043300df8d71132da766f373d2cb67d42feb2780572f062218")
        XCTAssert(initiationMessage.ephPublicKey == Data(base64Encoded: "MCowBQYDK2VwAyEA2QL4ri94/bwAI5sBabv//mNylwphNaIH9i+XcHyC31Y=")!)
        XCTAssert(initiationMessage.ephPublicKeySignature == Data(base64Encoded: "MFEwDQYJYIZIAWUDBAICBQAEQBzMAHMRw+OLGoC15iyVJzCjl3PvX5tFjl+/xcUdAAWLl6bBkzsxWa3Xi06X9CZXLlOw9LL0KKRSxIJ7flZAFwo=")!)
        XCTAssert(initiationMessage.salt == Data(base64Encoded: "9B+pj/IKvXD5dw4zGnV5+g==")!)
        XCTAssert(initiationMessage.initiatorIcId == "20c3374b6643841cd2da8277ee63ec3ecd4b10189b9e189102854112cc6755e7")
    }
    
    func test002_WeakInitiationMessage() {
        let testFileURL = Bundle(for: type(of: self)).url(forResource: "InitiationWeakMessageExample", withExtension: "txt")!
        let testFileData = try! Data(contentsOf: testFileURL)
        
        let initiationMessage = try! SecureSession.extractInitiationMessage(fromData: testFileData)
        
        XCTAssert(initiationMessage.responderIcId == "799d87cbc0022c5b10ef026da626e2863404228cb66a52009ee964a018724292")
        XCTAssert(initiationMessage.cipherText == Data(base64Encoded: "mhHJqPsr/oXdVftZMRjyKVLmeotdicg0")!)
        XCTAssert(initiationMessage.responderOtcId == nil)
        XCTAssert(initiationMessage.responderLtcId == "6911a2417a4ddd71721596c2b2db2c16062631f9e2397d2381266ea0736e3c44")
        XCTAssert(initiationMessage.ephPublicKey == Data(base64Encoded: "MCowBQYDK2VwAyEAit9SQ95k4L5fJTrg3m9O0D02S9ec468+fJ3tw4do7jU=")!)
        XCTAssert(initiationMessage.ephPublicKeySignature == Data(base64Encoded: "MFEwDQYJYIZIAWUDBAICBQAEQI0ZjJWiC6T6rVixYfyj1B4uY93hmohuzbob1QU3oiEDQ4RzS3N874p0+dxMX+SLE29OMIk9I4A54r8fiABUbwQ=")!)
        XCTAssert(initiationMessage.salt == Data(base64Encoded: "XIM/ZoEGyYYd5FUR6E1jIA==")!)
        XCTAssert(initiationMessage.initiatorIcId == "ea34ef3ea70f0b61ea02e40f358ff9381ac6fdec59377513c196cde4b45df988")
    }
    
    func test003_RegularMessage() {
        let testFileURL = Bundle(for: type(of: self)).url(forResource: "RegularMessageExample", withExtension: "txt")!
        let testFileData = try! Data(contentsOf: testFileURL)
        
        let message = try! SecureSession.extractMessage(fromData: testFileData)
        
        XCTAssert(message.cipherText == Data(base64Encoded: "NttiPDghzJM6nN26B0dlusMvh6RxApJdeRWAXQ==")!)
        XCTAssert(message.salt == Data(base64Encoded: "/p05lK7+QpswdTDOvcaRMg==")!)
        XCTAssert(message.sessionId == Data(base64Encoded: "vdPsqVXhmW9ysgoEIbWTl58yV+AC+vAeFsxiznC2avc=")!)
    }
}
