//
//  SessionState.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/23/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

protocol SessionState {
    init?(dictionary: Any, crypto: VSSCryptoProtocol)
    func serialize(crypto: VSSCryptoProtocol) -> NSObject
    var creationDate: Date { get }
}
