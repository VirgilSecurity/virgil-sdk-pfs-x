//
//  EphemeralCardValidator.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/15/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

class EphemeralCardValidator {
    let crypto: VSSCryptoProtocol
    private var verifiers: [String: VSSPublicKey] = [:]
    
    static let ErrorDomain = "EphemeralCardValidatorErrorDomain"
    
    init(crypto: VSSCryptoProtocol) {
        self.crypto = crypto
    }
    
    
    func addVerifier(withId verifierId: String, publicKeyData: Data) throws {
        guard let publicKey = self.crypto.importPublicKey(from: publicKeyData) else {
            throw NSError(domain: EphemeralCardValidator.ErrorDomain, code: -1, userInfo: [NSLocalizedDescriptionKey: "Error importing verifier public key."])
        }
        
        self.verifiers[verifierId] = publicKey
    }
    
    func validator(cardResponse: VSSCardResponse) -> Bool {
        let fingerprint = self.crypto.calculateFingerprint(for: cardResponse.snapshot)
        let cardId = fingerprint.hexValue
        
        guard cardId == cardResponse.identifier else {
            return false
        }
        
        for verifier in self.verifiers {
            guard let signature = cardResponse.signatures[verifier.key], signature.count > 0 else {
                return false
            }
            
            do {
                try self.crypto.verify(fingerprint.value, withSignature: signature, using: verifier.value)
            }
            catch {
                return false
            }
        }
        
        return true
    }
}
