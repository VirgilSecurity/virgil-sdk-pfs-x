//
//  SecureChat.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/20/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

@objc(VSPSecureChat) public class SecureChat: NSObject {
    public let preferences: SecureChatPreferences
    
    public init(preferences: SecureChatPreferences) {
        self.preferences = preferences
    }

    // FIXME
//    public func initTalk(withCardId cardId: String) -> SecureTalk {
//        return SecureTalk(crypto: self.preferences.crypto, recipientPublicKey: self.preferences., myPrivateKey: <#T##VSSPrivateKey#>)
//    }
}
