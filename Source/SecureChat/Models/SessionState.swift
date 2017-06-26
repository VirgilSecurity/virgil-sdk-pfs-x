//
//  SessionState.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/23/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilSDK

protocol SessionState: Serializable, Deserializable {
    var creationDate: Date { get }
    var sessionId: Data { get }
}
