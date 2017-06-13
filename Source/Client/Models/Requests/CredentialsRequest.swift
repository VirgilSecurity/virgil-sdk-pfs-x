//
//  CredentialsRequest.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

final class CredentialsRequest: NSObject {
    let identities: [String]
    
    init(identities: [String]) {
        self.identities = identities
    }
}

extension CredentialsRequest: Serializable {
    func serialize() -> Any {
        return [
            "identities": self.identities
        ]
    }
}
