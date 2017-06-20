//
//  SecureChat.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/20/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

@objc(VSPSecureChat) public class SecureChat: NSObject {
    public let preferences: SecureChatPreferences
    public let client: Client
    public let virgilClient: VSSClient
    
    public init(preferences: SecureChatPreferences) {
        self.preferences = preferences
        self.client = Client(serviceConfig: self.preferences.serviceConfig)
        self.virgilClient = VSSClient(serviceConfig: self.preferences.virgilServiceConfig)
    }

    public func initTalk(withCardId cardId: String, completion: @escaping (SecureTalk?, Error?)->()) {
        self.virgilClient.getCard(withId: cardId) { card, error in
            guard let card = card else {
                // FIXME
                completion(nil, nil)
                return
            }
            
            guard let publicKey = self.preferences.crypto.importPublicKey(from: card.publicKeyData) else {
                // FIXME
                completion(nil, nil)
                return
            }

            // FIXME
            let secureTalk = SecureTalk(crypto: self.preferences.crypto, myPrivateKey: self.preferences.crypto.generateKeyPair().privateKey, ephPrivateKey: self.preferences.crypto.generateKeyPair().privateKey, recipientPublicKey: publicKey, recipientLongTermKey: self.preferences.crypto.generateKeyPair().publicKey, recipientOneTimeKey: self.preferences.crypto.generateKeyPair().publicKey)
            
            completion(secureTalk, nil)
            return
        }
    }
}
