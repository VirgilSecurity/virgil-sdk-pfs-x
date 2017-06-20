//
//  SecureChatPreferences.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/20/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

@objc(VSPSecureChatPreferences) public class SecureChatPreferences: NSObject {
    public let myCardId: String
    public let myPrivateKey: VSSPrivateKey
    public let accessToken: String
    public let crypto: VSSCryptoProtocol
    public let keyStorage: VSSKeyStorageProtocol
    
    public init(myCardId: String, myPrivateKey: VSSPrivateKey, accessToken: String, crypto: VSSCryptoProtocol, keyStorage: VSSKeyStorageProtocol) {
        self.myCardId = myCardId
        self.myPrivateKey = myPrivateKey
        self.accessToken = accessToken
        self.crypto = crypto
        self.keyStorage = keyStorage
    }
}
