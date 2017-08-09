//
//  SecureChatErrorCode.swift
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 7/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

@objc(VSPSecureChatErrorCode) public enum SecureChatErrorCode: Int {
    case sessionNotFound
    case savingEphemeralKey
    case addingVerifier
    case longTermCardValidation
    case oneTimeCardValidation
    case checkingForExistingSession
    case foundActiveSession
    case removingExpiredSession
    case obtainingRecipientCardsSet
    case recipientSetEmpty
    case invalidMessageString
    case unknownMessageStructure
    case unknownSessionState
    case gettingEphemeralKeyFromStorage
    case removingEphAndOtKeys
    case removingEphKey
    case removingOtKey
    case oneOrMoreInitializationOperationsFailed
    case obtainingCardsStatus
    case bootstrapingEphemeralCards
    case addingOneTimeEphemeralCards
    case longTermKeyNotFoundAndNewKeyNowSpecified
    case tryingToRemoveKeysWithoutServiceEntry
    case loadingPrivateKey
    case creatingUserDefaults
    case corruptedSavedSession
    case anotherRotateKeysInProgress
    case encodingServiceInfo
    case decodingServiceInfo
}
