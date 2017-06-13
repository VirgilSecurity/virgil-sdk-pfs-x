//
//  PFSError.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

struct PFSError {
    let code: ErrorCode?
    
    var message: String {
        guard let code = self.code else {
            return "Unknown error"
        }
        
        let message: String
        
        switch code {
        case .serverInternal:            message = "Internal server error. Please try again later."
        case .accessToken:               message = "The Virgil access token or token header was not specified or is invalid"
        case .cardNotAvailable:          message = "The Virgil Card is not available in this application"
        case .invalidJson:               message = "JSON specified as a request is invalid"
        case .invalidSnapshot:           message = "Request snapshot invalid"
        case .signatureValidationFailed: message = "SCR sign validation failed (recipient)"
        case .selfSignatureMissing:      message = "SCR sign item is invalid or missing for the Client (Self sign)"
        case .globalCardScopeForbidden:  message = "Card scope should be application"
        case .maximumOtcNumberExceeded:  message = "Maximum number of OTCs 100"
        }
        
        return message
    }
    
    fileprivate init(code: Int) {
        guard let code = ErrorCode(rawValue: code) else {
            self.code = nil
            return
        }
        
        self.code = code
    }
}

extension PFSError: Deserializable {
    init?(dictionary: Any) {
        guard let dictionary = dictionary as? [String: Any] else {
            return nil
        }
        
        guard let code = dictionary["code"] as? NSNumber else {
            return nil
        }
        
        self.init(code: code.intValue)
    }
}

extension PFSError {
    enum ErrorCode: Int {
        case serverInternal            = 10000
        case accessToken               = 20300
        case cardNotAvailable          = 20500
        case invalidJson               = 30000
        case invalidSnapshot           = 30001
        case signatureValidationFailed = 30140
        case selfSignatureMissing      = 30142
        case globalCardScopeForbidden  = 60000
        case maximumOtcNumberExceeded  = 60010
    }
}

extension PFSError: Error { }
