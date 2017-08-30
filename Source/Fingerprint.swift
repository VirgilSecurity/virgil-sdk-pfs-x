//
//  Fingerprint.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 7/10/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCrypto

/// Error codes for NSError instances thrown from Fingerprint
@objc(VSPFingerprintErrorCode) public enum FingerpintErrorCode: Int {
    case invalidCardId
    case invalidHashLength
}

/// Class used to represent fingerprint of collection of card identifiers
@objc(VSPFingerprint) public class Fingerpint: NSObject {
    private static let Iterations = 4096
    
    /// Error domain for NSError instances thrown from here
    public static let ErrorDomain = "VSPFingerprintErrorDomain"
    
    /// Calculates fingerprint for given card identifiers
    ///
    /// NOTE: takes ~0.07s on iPhone 6
    ///
    /// - Parameter cardsIds: array of card identifiers
    /// - Returns: String with fingerpring
    /// - Throws: NSError instances with corresponding description
    public static func calculateFingerprint(forCardsIds cardsIds: [String]) throws -> String {
        let sortedCardsIds = cardsIds.sorted()
        
        let hash = VSCHash(algorithm: .SHA384)
        
        let cardsData = try sortedCardsIds.reduce(Data(), {
            guard let d = $1.data(using: .utf8) else {
                throw NSError(domain: Fingerpint.ErrorDomain, code: FingerpintErrorCode.invalidCardId.rawValue, userInfo: [NSLocalizedDescriptionKey: "Invalid card Id."])
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
            throw NSError(domain: Fingerpint.ErrorDomain, code: FingerpintErrorCode.invalidHashLength.rawValue, userInfo: [NSLocalizedDescriptionKey: "Invalid hash legnth."])
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
