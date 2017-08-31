//
//  SecureChat+MessageType.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 7/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

/// Message types used in PFS
@objc(VSPMessageType) public enum MessageType: Int {
    case unknown
    case initial
    case regular
}

// MARK: - Detecting message type
extension SecureChat {
    /// Returns message type
    ///
    /// - Parameter message: message
    /// - Returns: message type
    public class func getMessageType(_ message: String) -> MessageType {
        guard let messageData = message.data(using: .utf8) else {
            return .unknown
        }
        
        if (try? SecureSession.extractMessage(fromData: messageData)) != nil {
            return .regular
        }
        else if (try? SecureSession.extractInitiationMessage(fromData: messageData)) != nil {
            return .initial
        }
        
        return .unknown
    }
}
