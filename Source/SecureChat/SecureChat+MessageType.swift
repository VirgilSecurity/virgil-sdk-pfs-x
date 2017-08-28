//
//  SecureChat+MessageType.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 7/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

@objc(VSPMessageType) public enum MessageType: Int {
    case unknown
    case initial
    case regular
}

extension SecureChat {
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
