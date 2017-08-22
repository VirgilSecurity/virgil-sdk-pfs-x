//
//  SecureSessionErrorCode.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 7/27/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

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

    case sessionStillNotInitializedWhileEncryptingInInitiatorSession
    case convertingInitiationMessageToDataWhileEncrypting
    case encryptingInitiationMessage
    case convertingEncryptedInitiationMessageToUtf8Data
    case sessionStillNotInitializedWhileDecryptingInInitiatorSession
    case convertingEncryptedMessageToDataWhileDecryptingInInitiatorSession
    case convertingInitiatorKeysDuringInitiatorInitialization
    case instantiationInitiatorPrivateInfo
    case convertingResponderKeysDuringInitiatorInitialization
    case instantiationResponderPublicInfo
    case initiatingInitiatorSession

    case sessionStillNotInitializedWhileEncryptingInResponderSession
    case sessionStillNotInitializedWhileDecryptingInResponderSession
    case sessionIdIsMissing
    case convertingEncryptedMessageToDataWhileDecryptingInResponderSession
    case sessionStillNotInitializedWhileDecryptingInResponderSessionNotInitiationMessage
    case unknownMessageFormatWhileDecryptingInResponderSession
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
