//
//  SecureSessionErrorCode.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 7/27/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

/// Error codes for NSError instances thrown from SecureSession
@objc(VSPSecureSessionErrorCode) public enum SecureSessionErrorCode: Int {
    case convertingEncryptedMessageWhileDecrypting
    case decryptingMessage
    case convertingDecrypytedMessageToString
    case convertingMessageToDataWhileEncrypting
    case encryptingMessage
    case convertingEncryptedMessageToJson
    case convertingMessageToUtf8Data
    case decryptShouldBeOverridden
    case extractingInitiationMessage
    case extractingMessage
    case convertingEncryptedInitiationMessageToUtf8Data
    case convertingInitiatorKeysDuringInitiatorInitialization
    case instantiationInitiatorPrivateInfo
    case convertingResponderKeysDuringInitiatorInitialization
    case instantiationResponderPublicInfo
    case initiatingInitiatorSession
    case importingInitiatorPublicKeyFromIdentityCard
    case validatingInitiatorSignature
    case initiatorIdentityCardIdDoesntMatch
    case convertingResponderKeysDuringResponderInitialization
    case instantiationResponderPrivateInfo
    case convertingInitiatorKeysDuringResponderInitialization
    case instantiatingInitiatorPublicInfo
    case initiatingResponderSession
    case recoveringInitiatedSession
}
