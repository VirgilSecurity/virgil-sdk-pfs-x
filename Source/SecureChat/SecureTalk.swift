//
//  SecureTalk.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/20/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK
import VirgilCrypto

@objc(VSPSecureTalk) public class SecureTalk: NSObject {
    public let crypto: VSSCryptoProtocol
    public let recipientPublicKey: VSSPublicKey
    public let myPrivateKey: VSSPrivateKey
    
    init(crypto: VSSCryptoProtocol, recipientPublicKey: VSSPublicKey, myPrivateKey: VSSPrivateKey) {
        self.crypto = crypto
        self.recipientPublicKey = recipientPublicKey
        self.myPrivateKey = myPrivateKey
        
        super.init()
    }
    
    func encrypt(message: String) -> String {
        // FIXME
        return ""
    }
    
    func decrypt(encryptedMessage: String) -> String {
        // FIXME
        return ""
    }
}
