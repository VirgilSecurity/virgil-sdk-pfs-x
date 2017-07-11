//
//  Fingerprint.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 7/10/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCrypto

@objc(VSPFingerprint) public class Fingerpint: NSObject {
    private static let Iterations = 4096
    
    public static let ErrorDomain = "VSPFingerprintErrorDomain"
    
    // NOTE: takes ~0.07s on iPhone 6 
    public static func calculateFingerprint(forCardsIds cardsIds: [String]) throws -> String {
        let sortedCardsIds = cardsIds.sorted()
        
        let hash = VSCHash(algorithm: .SHA384)
        
        let cardsData = try sortedCardsIds.reduce(Data(), {
            guard let d = $1.data(using: .utf8) else {
                throw NSError(domain: Fingerpint.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid card Id."])
            }
            return $0 + d
        })
        
        var previousHash = Data()
        for _ in 0..<Fingerpint.Iterations {
            let data = cardsData + previousHash
            previousHash = hash!.hash(data)
        }
        
        return try self.hashToStr(hash: previousHash)
    }
    
    private static func hashToStr(hash: Data) throws -> String {
        guard hash.count == 48 else {
            throw NSError(domain: Fingerpint.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid hash legnth."])
        }
        
        var res = ""
        res.reserveCapacity(71)
        var num: UInt32 = 0
        var index = hash.startIndex
        for _ in stride(from: 0, to: 48, by: 4) {
            let endIndex = index.advanced(by: 4)
            num = hash.subdata(in: Range(uncheckedBounds: (index, endIndex))).withUnsafeBytes({ $0.pointee })

            index = endIndex
            num %= 100000
            
            res += String(format: "%05d ", num)
        }
        
        res.remove(at: res.index(before: res.endIndex))
        
        return res
    }
}
