//
//  VSP002_SessionTests.m
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/22/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>
#import "VSPTestsConst.h"
#import "VSPTestUtils.h"
@import VirgilSDK;
@import VirgilSDKPFS;

static const NSTimeInterval kEstimatedRequestCompletionTime = 8.;

@interface VSP002_SecureChatTests : XCTestCase

@property (nonatomic) VSPSecureChat *initiatorSecureChat;
@property (nonatomic) VSPSecureChat *initiatorSecureChat2;
@property (nonatomic) VSPSecureChat *responderSecureChat;
@property (nonatomic) VSPSecureChat *responderSecureChat2;
@property (nonatomic) VSSClient *virgilClient;
@property (nonatomic) VSSCardValidator *cardValidator;
@property (nonatomic) VSPClient *client;
@property (nonatomic) id<VSSCrypto> crypto;
@property (nonatomic) VSPTestsConst *consts;
@property (nonatomic) VSPTestUtils *utils;
@property (nonatomic) NSString *message1;
@property (nonatomic) NSString *message2;
@property (nonatomic) NSString *message3;
@property (nonatomic) NSString *message4;

@end

@implementation VSP002_SecureChatTests

- (void)setUp {
    [super setUp];
    self.consts = [[VSPTestsConst alloc] init];
    self.crypto = [[VSSCrypto alloc] initWithDefaultKeyType:VSSKeyTypeFAST_EC_ED25519];
    self.utils = [[VSPTestUtils alloc] initWithCrypto:self.crypto consts:self.consts];
    
    VSSServiceConfig *virgilConfig = [VSSServiceConfig serviceConfigWithToken:self.consts.applicationToken];
    
    self.cardValidator = [[VSSCardValidator alloc] initWithCrypto:self.crypto];
    VSSPrivateKey *privateKey = [self.crypto importPrivateKeyFromData:[[NSData alloc] initWithBase64EncodedString:self.consts.applicationPrivateKeyBase64 options:0]  withPassword:self.consts.applicationPrivateKeyPassword];
    VSSPublicKey *publicKey = [self.crypto extractPublicKeyFromPrivateKey:privateKey];
    NSData *publicKeyData = [self.crypto exportPublicKey:publicKey];
    XCTAssert([self.cardValidator addVerifierWithId:self.consts.applicationId publicKeyData:publicKeyData]);
    self.cardValidator.useVirgilServiceVerifiers = NO;
    virgilConfig.cardValidator = self.cardValidator;
    
    virgilConfig.cardsServiceURL = self.consts.cardsServiceURL;
    virgilConfig.cardsServiceROURL = self.consts.cardsServiceROURL;
    virgilConfig.registrationAuthorityURL = self.consts.registrationAuthorityURL;
    
    self.virgilClient = [[VSSClient alloc] initWithServiceConfig:virgilConfig];
    
    VSPServiceConfig *config = [[VSPServiceConfig alloc] initWithToken:self.consts.applicationToken ephemeralServiceURL:self.consts.pfsServiceURL];
    self.client = [[VSPClient alloc] initWithServiceConfig:config];
    
    self.message1 = @"message1";
    self.message2 = @"message2";
    self.message3 = @"message3";
    self.message4 = @"message4";
}

- (void)tearDown {
    [super tearDown];
}

- (void)test001_CreateAndInitializeSecureChat {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security session should be created"];
    
    NSUInteger numberOfRequests = 3;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime + 5;
    
    VSSKeyPair *keyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *identityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:keyPair];
    
    [self.virgilClient createCardWithRequest:identityRequest completion:^(VSSCard *card, NSError *error) {
        sleep(5);
        
        VSPSecureChatPreferences *preferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:keyPair.privateKey identityCard:card keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
        
        self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:preferences];
        
        [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
            XCTAssert(error == nil);
            
            [ex fulfill];
        }];
    }];
        
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test002_InitiateSecureSession {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security session should be created. Security session should be initiated."];
    
    NSUInteger numberOfRequests = 4;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime + 5;
    
    VSSKeyPair *keyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *identityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:keyPair];
    
    [self.virgilClient createCardWithRequest:identityRequest completion:^(VSSCard *card, NSError *error) {
        sleep(5);
        
        VSPSecureChatPreferences *preferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:keyPair.privateKey identityCard:card keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
        
        self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:preferences];
        
        [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
            [self.initiatorSecureChat startNewSessionWithRecipientWithCard:card additionalData:nil completion:^(VSPSecureSession *session, NSError *error) {
                XCTAssert(error == nil);
                XCTAssert(session != nil);
                [ex fulfill];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test003_SetupSession {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security session should be created. Security session should be initiated. Security session should be responded. Session should be created."];
    
    NSUInteger numberOfRequests = 8;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime + 5;
    
    VSSKeyPair *initiatorKeyPair = [self.crypto generateKeyPair];
    VSSKeyPair *responderKeyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *initiatorIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:initiatorKeyPair];
    VSSCreateCardRequest *responderIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:responderKeyPair];
    
    [self.virgilClient createCardWithRequest:initiatorIdentityRequest completion:^(VSSCard *initiatorCard, NSError *error) {
        [self.virgilClient createCardWithRequest:responderIdentityRequest completion:^(VSSCard *responderCard, NSError *error) {
            sleep(5);
            
            VSPSecureChatPreferences *initiatorPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:initiatorKeyPair.privateKey identityCard:initiatorCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
            
            VSPSecureChatPreferences *responderPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:responderKeyPair.privateKey identityCard:responderCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
            
            self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences];
            self.responderSecureChat = [[VSPSecureChat alloc] initWithPreferences:responderPreferences];
            
            [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
                [self.responderSecureChat initializeWithCompletion:^(NSError * error) {
                    [self.initiatorSecureChat startNewSessionWithRecipientWithCard:responderCard additionalData:nil completion:^(VSPSecureSession *initiatorSession, NSError *error) {
                        NSError *err;
                        NSString *encryptedMessage = [initiatorSession encrypt:self.message1 error:&err];
                        XCTAssert(err == nil);
                        XCTAssert(encryptedMessage.length > 0);
                        
                        VSPSecureSession *responderSession = [self.responderSecureChat loadUpSessionWithParticipantWithCard:initiatorCard message:encryptedMessage additionalData:nil error:&err];
                        XCTAssert(err == nil);
                        XCTAssert(responderSession != nil);
                        NSString *decryptedMessage = [responderSession decrypt:encryptedMessage error:&err];
                        XCTAssert(err == nil);
                        XCTAssert([self.message1 isEqualToString:decryptedMessage]);
                            
                        [ex fulfill];
                    }];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test004_SetupSessionEncryptDecrypt {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security session should be created. Security session should be initiated. Security session should be responded. Session should be created. Further encryption/decryption should work."];
    
    NSUInteger numberOfRequests = 8;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime + 5;
    
    VSSKeyPair *initiatorKeyPair = [self.crypto generateKeyPair];
    VSSKeyPair *responderKeyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *initiatorIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:initiatorKeyPair];
    VSSCreateCardRequest *responderIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:responderKeyPair];
    
    [self.virgilClient createCardWithRequest:initiatorIdentityRequest completion:^(VSSCard *initiatorCard, NSError *error) {
        [self.virgilClient createCardWithRequest:responderIdentityRequest completion:^(VSSCard *responderCard, NSError *error) {
            sleep(5);
            
            VSPSecureChatPreferences *initiatorPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:initiatorKeyPair.privateKey identityCard:initiatorCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
            
            VSPSecureChatPreferences *responderPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:responderKeyPair.privateKey identityCard:responderCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
            
            self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences];
            self.responderSecureChat = [[VSPSecureChat alloc] initWithPreferences:responderPreferences];
            
            [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
                [self.responderSecureChat initializeWithCompletion:^(NSError * error) {
                    [self.initiatorSecureChat startNewSessionWithRecipientWithCard:responderCard additionalData:nil completion:^(VSPSecureSession *initiatorSession, NSError *error) {
                        NSString *encryptedMessage1 = [initiatorSession encrypt:self.message1 error:nil];
                        
                        NSError *err;
                        VSPSecureSession *responderSession = [self.responderSecureChat loadUpSessionWithParticipantWithCard:initiatorCard message:encryptedMessage1 additionalData:nil error:&err];
                        XCTAssert(err == nil);
                        XCTAssert(responderSession != nil);
                        NSString *decryptedMessage1 = [responderSession decrypt:encryptedMessage1 error:&err];
                        XCTAssert(err == nil);
                        XCTAssert([self.message1 isEqualToString:decryptedMessage1]);
                        
                        NSString *encryptedMessage2 = [initiatorSession encrypt:self.message2 error:&err];
                        XCTAssert(err == nil);
                        NSString *message2 = [responderSession decrypt:encryptedMessage2 error:&err];
                        XCTAssert(err == nil);
                        XCTAssert([self.message2 isEqualToString:message2]);
                        
                        NSString *encryptedMessage3 = [responderSession encrypt:self.message3 error:&err];
                        XCTAssert(err == nil);
                        NSString *message3 = [initiatorSession decrypt:encryptedMessage3 error:&err];
                        XCTAssert(err == nil);
                        XCTAssert([self.message3 isEqualToString:message3]);
                        
                        [ex fulfill];
                    }];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test005_RecoverInitiatorSession {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security session should be created. Security session should be initiated. Security session should be responded. Session should be created. Initiator session should be recovered. Further encryption/decryption should work."];
    
    NSUInteger numberOfRequests = 9;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime + 5;
    
    VSSKeyPair *initiatorKeyPair = [self.crypto generateKeyPair];
    VSSKeyPair *responderKeyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *initiatorIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:initiatorKeyPair];
    VSSCreateCardRequest *responderIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:responderKeyPair];
    
    [self.virgilClient createCardWithRequest:initiatorIdentityRequest completion:^(VSSCard *initiatorCard, NSError *error) {
        [self.virgilClient createCardWithRequest:responderIdentityRequest completion:^(VSSCard *responderCard, NSError *error) {
            sleep(5);
            
            VSPSecureChatPreferences *initiatorPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:initiatorKeyPair.privateKey identityCard:initiatorCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
            
            VSPSecureChatPreferences *responderPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:responderKeyPair.privateKey identityCard:responderCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
            
            self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences];
            self.responderSecureChat = [[VSPSecureChat alloc] initWithPreferences:responderPreferences];
            
            [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
                [self.responderSecureChat initializeWithCompletion:^(NSError * error) {
                    [self.initiatorSecureChat startNewSessionWithRecipientWithCard:responderCard additionalData:nil completion:^(VSPSecureSession *initiatorSession, NSError *error) {
                        NSString *encryptedMessage1 = [initiatorSession encrypt:self.message1 error:nil];
                        
                        VSPSecureSession *responderSession = [self.responderSecureChat loadUpSessionWithParticipantWithCard:initiatorCard message:encryptedMessage1 additionalData:nil error:nil];
                        
                        VSPSecureSession *recoveredInitiatorSession = [self.initiatorSecureChat activeSessionWithParticipantWithCardId:responderCard.identifier];
                        XCTAssert(recoveredInitiatorSession != nil);
                        NSError *err;
                        NSString *encryptedMessage2 = [recoveredInitiatorSession encrypt:self.message2 error:&err];
                        XCTAssert(err == nil);
                        NSString *message2 = [responderSession decrypt:encryptedMessage2 error:&err];
                        XCTAssert(err == nil);
                        XCTAssert([self.message2 isEqualToString:message2]);
                        
                        [ex fulfill];
                    }];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test006_RecoverInitiatorSessionWithMessage {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security session should be created. Security session should be initiated. Security session should be responded. Session should be created. Initiator session should be recovered using message. Further encryption/decryption should work."];
    
    NSUInteger numberOfRequests = 9;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime + 5;
    
    VSSKeyPair *initiatorKeyPair = [self.crypto generateKeyPair];
    VSSKeyPair *responderKeyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *initiatorIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:initiatorKeyPair];
    VSSCreateCardRequest *responderIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:responderKeyPair];
    
    [self.virgilClient createCardWithRequest:initiatorIdentityRequest completion:^(VSSCard *initiatorCard, NSError *error) {
        [self.virgilClient createCardWithRequest:responderIdentityRequest completion:^(VSSCard *responderCard, NSError *error) {
            sleep(5);
            
            VSPSecureChatPreferences *initiatorPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:initiatorKeyPair.privateKey identityCard:initiatorCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
            
            VSPSecureChatPreferences *responderPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:responderKeyPair.privateKey identityCard:responderCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
            
            self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences];
            self.responderSecureChat = [[VSPSecureChat alloc] initWithPreferences:responderPreferences];
            
            [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
                [self.responderSecureChat initializeWithCompletion:^(NSError * error) {
                    [self.initiatorSecureChat startNewSessionWithRecipientWithCard:responderCard additionalData:nil completion:^(VSPSecureSession *initiatorSession, NSError *error) {
                        NSString *encryptedMessage1 = [initiatorSession encrypt:self.message1 error:nil];
                        
                        VSPSecureSession *responderSession = [self.responderSecureChat loadUpSessionWithParticipantWithCard:initiatorCard message:encryptedMessage1 additionalData:nil error:nil];
                        NSString *encryptedMessage2 = [responderSession encrypt:self.message2 error:nil];
                        
                        NSError *err;
                        VSPSecureSession *recoveredInitiatorSession = [self.initiatorSecureChat loadUpSessionWithParticipantWithCard:responderCard message:encryptedMessage2 additionalData:nil error:&err];
                        XCTAssert(err == nil);
                        XCTAssert(recoveredInitiatorSession != nil);
                        NSString *message2 = [recoveredInitiatorSession decrypt:encryptedMessage2 error:&err];
                        XCTAssert(err == nil);
                        XCTAssert([self.message2 isEqualToString:message2]);
                        
                        [ex fulfill];
                    }];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test007_RecoverResponderSession {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security session should be created. Security session should be initiated. Security session should be responded. Session should be created. Responder session should be recovered. Further encryption/decryption should work."];
    
    NSUInteger numberOfRequests = 9;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime + 5;
    
    VSSKeyPair *initiatorKeyPair = [self.crypto generateKeyPair];
    VSSKeyPair *responderKeyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *initiatorIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:initiatorKeyPair];
    VSSCreateCardRequest *responderIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:responderKeyPair];
    
    [self.virgilClient createCardWithRequest:initiatorIdentityRequest completion:^(VSSCard *initiatorCard, NSError *error) {
        [self.virgilClient createCardWithRequest:responderIdentityRequest completion:^(VSSCard *responderCard, NSError *error) {
            sleep(5);
            
            VSPSecureChatPreferences *initiatorPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:initiatorKeyPair.privateKey identityCard:initiatorCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
            
            VSPSecureChatPreferences *responderPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:responderKeyPair.privateKey identityCard:responderCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
            
            self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences];
            self.responderSecureChat = [[VSPSecureChat alloc] initWithPreferences:responderPreferences];
            
            [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
                [self.responderSecureChat initializeWithCompletion:^(NSError * error) {
                    [self.initiatorSecureChat startNewSessionWithRecipientWithCard:responderCard additionalData:nil completion:^(VSPSecureSession *initiatorSession, NSError *error) {
                        NSString *encryptedMessage1 = [initiatorSession encrypt:self.message1 error:nil];
                        
                        VSPSecureSession __unused *responderSession = [self.responderSecureChat loadUpSessionWithParticipantWithCard:initiatorCard message:encryptedMessage1 additionalData:nil error:nil];
                        
                        VSPSecureSession *recoveredResponderSession = [self.responderSecureChat activeSessionWithParticipantWithCardId:initiatorCard.identifier];
                        XCTAssert(recoveredResponderSession != nil);
                        NSError *err;
                        NSString *encryptedMessage2 = [initiatorSession encrypt:self.message2 error:&err];
                        XCTAssert(err == nil);
                        NSString *message2 = [recoveredResponderSession decrypt:encryptedMessage2 error:&err];
                        XCTAssert(err == nil);
                        XCTAssert([self.message2 isEqualToString:message2]);
                        
                        [ex fulfill];
                    }];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test008_RecoverResponderSessionWithMessage {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security session should be created. Security session should be initiated. Security session should be responded. Session should be created. Responder session should be recovered using message. Further encryption/decryption should work."];
    
    NSUInteger numberOfRequests = 9;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime + 5;
    
    VSSKeyPair *initiatorKeyPair = [self.crypto generateKeyPair];
    VSSKeyPair *responderKeyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *initiatorIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:initiatorKeyPair];
    VSSCreateCardRequest *responderIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:responderKeyPair];
    
    [self.virgilClient createCardWithRequest:initiatorIdentityRequest completion:^(VSSCard *initiatorCard, NSError *error) {
        [self.virgilClient createCardWithRequest:responderIdentityRequest completion:^(VSSCard *responderCard, NSError *error) {
            sleep(5);
            
            VSPSecureChatPreferences *initiatorPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:initiatorKeyPair.privateKey identityCard:initiatorCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
            
            VSPSecureChatPreferences *responderPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:responderKeyPair.privateKey identityCard:responderCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
            
            self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences];
            self.responderSecureChat = [[VSPSecureChat alloc] initWithPreferences:responderPreferences];
            
            [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
                [self.responderSecureChat initializeWithCompletion:^(NSError * error) {
                    [self.initiatorSecureChat startNewSessionWithRecipientWithCard:responderCard additionalData:nil completion:^(VSPSecureSession *initiatorSession, NSError *error) {
                        NSString *encryptedMessage1 = [initiatorSession encrypt:self.message1 error:nil];
                        
                        VSPSecureSession __unused *responderSession = [self.responderSecureChat loadUpSessionWithParticipantWithCard:initiatorCard message:encryptedMessage1 additionalData:nil error:nil];
                        
                        NSString *encryptedMessage2 = [initiatorSession encrypt:self.message2 error:nil];
                        
                        NSError *err;
                        VSPSecureSession *recoveredResponderSession = [self.responderSecureChat loadUpSessionWithParticipantWithCard:initiatorCard message:encryptedMessage2 additionalData:nil error:&err];
                        NSString *message2 = [recoveredResponderSession decrypt:encryptedMessage2 error:&err];
                        XCTAssert(err == nil);
                        XCTAssert(recoveredResponderSession != nil);
                        XCTAssert([self.message2 isEqualToString:message2]);
                        
                        [ex fulfill];
                    }];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test009_ExpireInitiatorSession {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security session should be created. Security session should be initiated. Security session should be responded. Session should be created. Initiator secure chat should be initialized."];
    
    NSUInteger numberOfRequests = 9;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime + 5;
    
    VSSKeyPair *initiatorKeyPair = [self.crypto generateKeyPair];
    VSSKeyPair *responderKeyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *initiatorIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:initiatorKeyPair];
    VSSCreateCardRequest *responderIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:responderKeyPair];
    
    [self.virgilClient createCardWithRequest:initiatorIdentityRequest completion:^(VSSCard *initiatorCard, NSError *error) {
        [self.virgilClient createCardWithRequest:responderIdentityRequest completion:^(VSSCard *responderCard, NSError *error) {
            sleep(5);
            
            VSPSecureChatPreferences *initiatorPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:initiatorKeyPair.privateKey identityCard:initiatorCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
            
            VSPSecureChatPreferences *responderPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:responderKeyPair.privateKey identityCard:responderCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
            
            self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences];
            self.responderSecureChat = [[VSPSecureChat alloc] initWithPreferences:responderPreferences];
            
            [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
                [self.responderSecureChat initializeWithCompletion:^(NSError * error) {
                    [self.initiatorSecureChat startNewSessionWithRecipientWithCard:responderCard additionalData:nil completion:^(VSPSecureSession *initiatorSession, NSError *error) {
                        NSString *encryptedMessage1 = [initiatorSession encrypt:self.message1 error:nil];
                        
                        VSPSecureSession __unused *responderSession = [self.responderSecureChat loadUpSessionWithParticipantWithCard:initiatorCard message:encryptedMessage1 additionalData:nil error:nil];
                        
                        NSString __unused *encryptedMessage2 = [initiatorSession encrypt:self.message2 error:nil];
                        
                        self.initiatorSecureChat2 = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences];
                        
                        [self.initiatorSecureChat2 initializeWithCompletion:^(NSError *error) {
                            XCTAssert(error == nil);
                            
                            [ex fulfill];
                        }];
                    }];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test010_ExpireResponderSession {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security session should be created. Security session should be initiated. Security session should be responded. Session should be created. Responder secure chat should be initialized."];
    
    NSUInteger numberOfRequests = 9;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime + 5;
    
    VSSKeyPair *initiatorKeyPair = [self.crypto generateKeyPair];
    VSSKeyPair *responderKeyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *initiatorIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:initiatorKeyPair];
    VSSCreateCardRequest *responderIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:responderKeyPair];
    
    [self.virgilClient createCardWithRequest:initiatorIdentityRequest completion:^(VSSCard *initiatorCard, NSError *error) {
        [self.virgilClient createCardWithRequest:responderIdentityRequest completion:^(VSSCard *responderCard, NSError *error) {
            sleep(5);
            
            VSPSecureChatPreferences *initiatorPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:initiatorKeyPair.privateKey identityCard:initiatorCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
            
            VSPSecureChatPreferences *responderPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:responderKeyPair.privateKey identityCard:responderCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
            
            self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences];
            self.responderSecureChat = [[VSPSecureChat alloc] initWithPreferences:responderPreferences];
            
            [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
                [self.responderSecureChat initializeWithCompletion:^(NSError * error) {
                    [self.initiatorSecureChat startNewSessionWithRecipientWithCard:responderCard additionalData:nil completion:^(VSPSecureSession *initiatorSession, NSError *error) {
                        NSString *encryptedMessage1 = [initiatorSession encrypt:self.message1 error:nil];
                        
                        VSPSecureSession __unused *responderSession = [self.responderSecureChat loadUpSessionWithParticipantWithCard:initiatorCard message:encryptedMessage1 additionalData:nil error:nil];
                        
                        NSString __unused *encryptedMessage2 = [initiatorSession encrypt:self.message2 error:nil];
                        
                        self.responderSecureChat2 = [[VSPSecureChat alloc] initWithPreferences:responderPreferences];
                        
                        [self.responderSecureChat2 initializeWithCompletion:^(NSError *error) {
                            XCTAssert(error == nil);
                            
                            [ex fulfill];
                        }];
                    }];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test011_ExpireLongTermCard {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security session should be created. LongTerm card should be added. LongTerm card should expire."];
    
    NSUInteger numberOfRequests = 9;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime + 5 + 10;
    
    VSSKeyPair *initiatorKeyPair = [self.crypto generateKeyPair];
    VSSKeyPair *responderKeyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *initiatorIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:initiatorKeyPair];
    VSSCreateCardRequest *responderIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:responderKeyPair];
    
    NSString * __block longTermId1, * __block longTermId2, * __block oneTimeId1, * __block oneTimeId2;
    
    [self.virgilClient createCardWithRequest:initiatorIdentityRequest completion:^(VSSCard *initiatorCard, NSError *error) {
        [self.virgilClient createCardWithRequest:responderIdentityRequest completion:^(VSSCard *responderCard, NSError *error) {
            sleep(5);
            
            VSPSecureChatPreferences *initiatorPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:initiatorKeyPair.privateKey identityCard:initiatorCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
            VSPSecureChatPreferences *responderPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:responderKeyPair.privateKey identityCard:responderCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:[[NSNumber alloc] initWithDouble:5] sessionTtl:nil];
            
            self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences];
            self.responderSecureChat = [[VSPSecureChat alloc] initWithPreferences:responderPreferences];
            
            [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
                [self.responderSecureChat initializeWithCompletion:^(NSError * error) {
                    [self.client getRecipientCardsSetForCardsIds:@[responderCard.identifier] completion:^(NSArray<VSPRecipientCardsSet *> *cardsSet, NSError *error) {
                        XCTAssert(error == nil);
                        XCTAssert(cardsSet.count == 1);
                        VSPRecipientCardsSet *cardSet = cardsSet[0];
                        longTermId1 = cardSet.longTermCard.identifier;
                        oneTimeId1 = cardSet.oneTimeCard.identifier;
                        
                        [self.initiatorSecureChat startNewSessionWithRecipientWithCard:responderCard additionalData:nil completion:^(VSPSecureSession *initiatorSession, NSError *error) {
                            NSError *err;
                            NSString *encryptedMessage1 = [initiatorSession encrypt:self.message1 error:&err];
                            XCTAssert(err == nil);
                            
                            VSPSecureSession *responderSession = [self.responderSecureChat loadUpSessionWithParticipantWithCard:initiatorCard message:encryptedMessage1 additionalData:nil error:&err];
                            XCTAssert(err == nil);
                            NSString *message1 = [responderSession decrypt:encryptedMessage1 error:&err];
                            XCTAssert(err == nil);
                            XCTAssert([self.message1 isEqualToString:message1]);
                            
                            sleep(10);
                            
                            [self.responderSecureChat initializeWithCompletion:^(NSError *error) {
                                [self.client getRecipientCardsSetForCardsIds:@[responderCard.identifier] completion:^(NSArray<VSPRecipientCardsSet *> *cardsSet, NSError *error) {
                                    XCTAssert(error == nil);
                                    XCTAssert(cardsSet.count == 1);
                                    VSPRecipientCardsSet *cardSet = cardsSet[0];
                                    longTermId2 = cardSet.longTermCard.identifier;
                                    oneTimeId2 = cardSet.oneTimeCard.identifier;
                                    
                                    XCTAssert(longTermId1.length > 0);
                                    XCTAssert(longTermId2.length > 0);
                                    XCTAssert(![longTermId1 isEqualToString:longTermId2]);
                                    
                                    XCTAssert(oneTimeId1.length > 0);
                                    XCTAssert(oneTimeId2.length > 0);
                                    XCTAssert(![oneTimeId1 isEqualToString:oneTimeId2]);
                                    
                                    NSError *err;
                                    NSString *encryptedMessage2 = [initiatorSession encrypt:self.message2 error:&err];
                                    XCTAssert(err == nil);
                                    
                                    VSPSecureSession *responderSession = [self.responderSecureChat loadUpSessionWithParticipantWithCard:initiatorCard message:encryptedMessage2 additionalData:nil error:&err];
                                    XCTAssert(err == nil);
                                    NSString *message2 = [responderSession decrypt:encryptedMessage2 error:&err];
                                    XCTAssert(err == nil);
                                    XCTAssert([self.message2 isEqualToString:message2]);
                                    
                                    [ex fulfill];
                                }];
                            }];
                        }];
                    }];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test012_ForceWeakSession {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security session should be created. OTC cards should end. Weak session should be started."];
    
    NSUInteger numberOfRequests = 7;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime + 5;
    
    VSSKeyPair *initiatorKeyPair = [self.crypto generateKeyPair];
    VSSKeyPair *responderKeyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *initiatorIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:initiatorKeyPair];
    VSSCreateCardRequest *responderIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:responderKeyPair];
    
    [self.virgilClient createCardWithRequest:initiatorIdentityRequest completion:^(VSSCard *initiatorCard, NSError *error) {
        [self.virgilClient createCardWithRequest:responderIdentityRequest completion:^(VSSCard *responderCard, NSError *error) {
            sleep(5);
            
            VSPSecureChatPreferences *initiatorPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:initiatorKeyPair.privateKey identityCard:initiatorCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
            VSPSecureChatPreferences *responderPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:responderKeyPair.privateKey identityCard:responderCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:[[NSNumber alloc] initWithInt:1] longTermKeysTtl:nil sessionTtl:nil];
            
            self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences];
            self.responderSecureChat = [[VSPSecureChat alloc] initWithPreferences:responderPreferences];
            
            [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
                [self.responderSecureChat initializeWithCompletion:^(NSError *error) {
                    [self.client getRecipientCardsSetForCardsIds:@[responderCard.identifier] completion:^(NSArray<VSPRecipientCardsSet *> *cardsSet, NSError *error) {
                        XCTAssert(cardsSet[0].oneTimeCard.identifier.length > 0);
                    
                        [self.client getRecipientCardsSetForCardsIds:@[responderCard.identifier] completion:^(NSArray<VSPRecipientCardsSet *> *cardsSet, NSError *error) {
                            XCTAssert(error == nil);
                            XCTAssert(cardsSet[0].longTermCard != nil);
                            XCTAssert(cardsSet[0].oneTimeCard == nil);
                            
                            [self.initiatorSecureChat startNewSessionWithRecipientWithCard:responderCard additionalData:nil completion:^(VSPSecureSession *initiatorSession, NSError *error) {
                                XCTAssert(error == nil);
                                XCTAssert(initiatorSession != nil);
                                
                                NSString *encryptedMessage1 = [initiatorSession encrypt:self.message1 error:nil];
                                
                                NSError *err;
                                VSPSecureSession *responderSession = [self.responderSecureChat loadUpSessionWithParticipantWithCard:initiatorCard message:encryptedMessage1 additionalData:nil error:&err];
                                XCTAssert(err == nil);
                                XCTAssert(responderSession != nil);
                                NSString *decryptedMessage1 = [responderSession decrypt:encryptedMessage1 error:&err];
                                XCTAssert(err == nil);
                                XCTAssert([self.message1 isEqualToString:decryptedMessage1]);
                                
                                NSString *encryptedMessage2 = [initiatorSession encrypt:self.message2 error:&err];
                                XCTAssert(err == nil);
                                NSString *message2 = [responderSession decrypt:encryptedMessage2 error:&err];
                                XCTAssert(err == nil);
                                XCTAssert([self.message2 isEqualToString:message2]);
                                
                                NSString *encryptedMessage3 = [responderSession encrypt:self.message3 error:&err];
                                XCTAssert(err == nil);
                                NSString *message3 = [initiatorSession decrypt:encryptedMessage3 error:&err];
                                XCTAssert(err == nil);
                                XCTAssert([self.message3 isEqualToString:message3]);
                                
                                [ex fulfill];
                            }];
                        }];
                    }];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test013_Start2SeparateResponderSessions {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security session should be created. LongTerm card should be added."];
    
    NSUInteger numberOfRequests = 11;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime + 5;
    
    VSSKeyPair *initiatorKeyPair = [self.crypto generateKeyPair];
    VSSKeyPair *responderKeyPair1 = [self.crypto generateKeyPair];
    VSSKeyPair *responderKeyPair2 = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *initiatorIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:initiatorKeyPair];
    VSSCreateCardRequest *responderIdentityRequest1 = [self.utils instantiateCreateCardRequestWithKeyPair:responderKeyPair1];
    VSSCreateCardRequest *responderIdentityRequest2 = [self.utils instantiateCreateCardRequestWithKeyPair:responderKeyPair2];
    
    [self.virgilClient createCardWithRequest:initiatorIdentityRequest completion:^(VSSCard *initiatorCard, NSError *error) {
        [self.virgilClient createCardWithRequest:responderIdentityRequest1 completion:^(VSSCard *responderCard1, NSError *error) {
            [self.virgilClient createCardWithRequest:responderIdentityRequest2 completion:^(VSSCard *responderCard2, NSError *error) {
                sleep(5);
                
                VSPSecureChatPreferences *initiatorPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:initiatorKeyPair.privateKey identityCard:initiatorCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
                VSPSecureChatPreferences *responderPreferences1 = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:responderKeyPair1.privateKey identityCard:responderCard1 keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
                VSPSecureChatPreferences *responderPreferences2 = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:responderKeyPair2.privateKey identityCard:responderCard2 keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
                
                self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences];
                self.responderSecureChat = [[VSPSecureChat alloc] initWithPreferences:responderPreferences1];
                self.responderSecureChat2 = [[VSPSecureChat alloc] initWithPreferences:responderPreferences2];
                
                [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
                    [self.responderSecureChat initializeWithCompletion:^(NSError *error) {
                        [self.responderSecureChat2 initializeWithCompletion:^(NSError *error) {
                            [self.initiatorSecureChat startNewSessionWithRecipientWithCard:responderCard1 additionalData:nil completion:^(VSPSecureSession *initiatorSession1, NSError *error) {
                                XCTAssert(error == nil);
                                XCTAssert(initiatorSession1 != nil);
                                
                                NSError *err;
                                
                                NSString *encryptedMessage11 = [initiatorSession1 encrypt:self.message1 error:&err];
                                
                                VSPSecureSession *responderSession1 = [self.responderSecureChat loadUpSessionWithParticipantWithCard:initiatorCard message:encryptedMessage11 additionalData:nil error:&err];
                                XCTAssert(err == nil);
                                XCTAssert(responderSession1 != nil);
                                NSString *decryptedMessage11 = [responderSession1 decrypt:encryptedMessage11 error:&err];
                                XCTAssert(err == nil);
                                XCTAssert([self.message1 isEqualToString:decryptedMessage11]);
                                
                                [self.initiatorSecureChat startNewSessionWithRecipientWithCard:responderCard2 additionalData:nil completion:^(VSPSecureSession *initiatorSession2, NSError *error) {
                                    XCTAssert(error == nil);
                                    XCTAssert(initiatorSession2 != nil);
                                    
                                    NSError *err;
                                    
                                    NSString *encryptedMessage22 = [initiatorSession2 encrypt:self.message2 error:&err];
                                    XCTAssert(err == nil);
                                    XCTAssert(encryptedMessage22.length > 0);
                                    
                                    VSPSecureSession *foreignSession = [self.responderSecureChat2 activeSessionWithParticipantWithCardId:initiatorCard.identifier];
                                    XCTAssert(foreignSession == nil);
                                    
                                    VSPSecureSession *responderSession2 = [self.responderSecureChat2 loadUpSessionWithParticipantWithCard:initiatorCard message:encryptedMessage22 additionalData:nil error:&err];
                                    XCTAssert(err == nil);
                                    XCTAssert(responderSession2 != nil);
                                    
                                    NSString *decryptedMessage22 = [responderSession2 decrypt:encryptedMessage22 error:&err];
                                    XCTAssert(err == nil);
                                    XCTAssert([self.message2 isEqualToString:decryptedMessage22]);
                                    
                                    [ex fulfill];
                                }];
                            }];
                        }];
                    }];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test014_Start2SeparateInitiatorSessions {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security session should be created. LongTerm card should be added."];
    
    NSUInteger numberOfRequests = 11;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime + 5;
    
    VSSKeyPair *initiatorKeyPair1 = [self.crypto generateKeyPair];
    VSSKeyPair *initiatorKeyPair2 = [self.crypto generateKeyPair];
    VSSKeyPair *responderKeyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *initiatorIdentityRequest1 = [self.utils instantiateCreateCardRequestWithKeyPair:initiatorKeyPair1];
    VSSCreateCardRequest *initiatorIdentityRequest2 = [self.utils instantiateCreateCardRequestWithKeyPair:initiatorKeyPair2];
    VSSCreateCardRequest *responderIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:responderKeyPair];
    
    [self.virgilClient createCardWithRequest:initiatorIdentityRequest1 completion:^(VSSCard *initiatorCard1, NSError *error) {
        [self.virgilClient createCardWithRequest:initiatorIdentityRequest2 completion:^(VSSCard *initiatorCard2, NSError *error) {
            [self.virgilClient createCardWithRequest:responderIdentityRequest completion:^(VSSCard *responderCard, NSError *error) {
                sleep(5);
                
                VSPSecureChatPreferences *initiatorPreferences1 = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:initiatorKeyPair1.privateKey identityCard:initiatorCard1 keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
                VSPSecureChatPreferences *initiatorPreferences2 = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:initiatorKeyPair2.privateKey identityCard:initiatorCard2 keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
                VSPSecureChatPreferences *responderPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:responderKeyPair.privateKey identityCard:responderCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
                
                self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences1];
                self.initiatorSecureChat2 = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences2];
                self.responderSecureChat = [[VSPSecureChat alloc] initWithPreferences:responderPreferences];
                
                [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
                    [self.initiatorSecureChat2 initializeWithCompletion:^(NSError *error) {
                        [self.responderSecureChat initializeWithCompletion:^(NSError *error) {
                            [self.initiatorSecureChat startNewSessionWithRecipientWithCard:responderCard additionalData:nil completion:^(VSPSecureSession *initiatorSession1, NSError *error) {
                                XCTAssert(error == nil);
                                XCTAssert(initiatorSession1 != nil);
                                
                                NSError *err;
                                
                                NSString *encryptedMessage11 = [initiatorSession1 encrypt:self.message1 error:&err];
                                
                                VSPSecureSession *responderSession1 = [self.responderSecureChat loadUpSessionWithParticipantWithCard:initiatorCard1 message:encryptedMessage11 additionalData:nil error:&err];
                                XCTAssert(err == nil);
                                XCTAssert(responderSession1 != nil);
                                NSString *decryptedMessage11 = [responderSession1 decrypt:encryptedMessage11 error:&err];
                                XCTAssert(err == nil);
                                XCTAssert([self.message1 isEqualToString:decryptedMessage11]);
                                
                                VSPSecureSession *foreignSession = [self.initiatorSecureChat2 activeSessionWithParticipantWithCardId:responderCard.identifier];
                                XCTAssert(foreignSession == nil);
                                
                                [self.initiatorSecureChat2 startNewSessionWithRecipientWithCard:responderCard additionalData:nil completion:^(VSPSecureSession *initiatorSession2, NSError *error) {
                                    XCTAssert(error == nil);
                                    XCTAssert(initiatorSession2 != nil);
                                    
                                    NSError *err;
                                    
                                    NSString *encryptedMessage22 = [initiatorSession2 encrypt:self.message2 error:&err];
                                    XCTAssert(err == nil);
                                    XCTAssert(encryptedMessage22.length > 0);
                                    
                                    VSPSecureSession *responderSession2 = [self.responderSecureChat loadUpSessionWithParticipantWithCard:initiatorCard2 message:encryptedMessage22 additionalData:nil error:&err];
                                    XCTAssert(err == nil);
                                    XCTAssert(responderSession2 != nil);
                                    
                                    NSString *decryptedMessage22 = [responderSession2 decrypt:encryptedMessage22 error:&err];
                                    XCTAssert(err == nil);
                                    XCTAssert([self.message2 isEqualToString:decryptedMessage22]);
                                    
                                    [ex fulfill];
                                }];
                            }];
                        }];
                    }];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test015_RemoveActiveSession {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security session should be created. Security session should be initiated. Security session should be responded. Session should be created. Session should be removed on both sides."];
    
    NSUInteger numberOfRequests = 8;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime + 5;
    
    VSSKeyPair *initiatorKeyPair = [self.crypto generateKeyPair];
    VSSKeyPair *responderKeyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *initiatorIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:initiatorKeyPair];
    VSSCreateCardRequest *responderIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:responderKeyPair];
    
    [self.virgilClient createCardWithRequest:initiatorIdentityRequest completion:^(VSSCard *initiatorCard, NSError *error) {
        [self.virgilClient createCardWithRequest:responderIdentityRequest completion:^(VSSCard *responderCard, NSError *error) {
            sleep(5);
            
            VSPSecureChatPreferences *initiatorPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:initiatorKeyPair.privateKey identityCard:initiatorCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
            
            VSPSecureChatPreferences *responderPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:responderKeyPair.privateKey identityCard:responderCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
            
            self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences];
            self.responderSecureChat = [[VSPSecureChat alloc] initWithPreferences:responderPreferences];
            
            [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
                [self.responderSecureChat initializeWithCompletion:^(NSError * error) {
                    [self.initiatorSecureChat startNewSessionWithRecipientWithCard:responderCard additionalData:nil completion:^(VSPSecureSession *initiatorSession, NSError *error) {
                        NSError *err;
                        
                        NSString *encryptedMessage1 = [initiatorSession encrypt:self.message1 error:&err];
                        XCTAssert(err == nil);
                        
                        BOOL res = [self.initiatorSecureChat removeSessionWithParticipantWithCardId:responderCard.identifier error:&err];
                        XCTAssert(res == YES && err == nil);
                        
                        VSPSecureSession *removedInitiatorSession = [self.initiatorSecureChat activeSessionWithParticipantWithCardId:responderCard.identifier];
                        XCTAssert(removedInitiatorSession == nil);
                        
                        VSPSecureSession *responderSession = [self.responderSecureChat loadUpSessionWithParticipantWithCard:initiatorCard message:encryptedMessage1 additionalData:nil error:&err];
                        XCTAssert(err == nil);
                        XCTAssert(responderSession != nil);
                        NSString *decryptedMessage1 = [responderSession decrypt:encryptedMessage1 error:&err];
                        XCTAssert(err == nil);
                        XCTAssert([self.message1 isEqualToString:decryptedMessage1]);
                        
                        res = [self.responderSecureChat removeSessionWithParticipantWithCardId:initiatorCard.identifier error:&err];
                        XCTAssert(res == YES && err == nil);
                        
                        VSPSecureSession *removedResponderSession = [self.initiatorSecureChat activeSessionWithParticipantWithCardId:initiatorCard.identifier];
                        XCTAssert(removedResponderSession == nil);
                        
                        [ex fulfill];
                    }];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test015_RecreateRemovedActiveSession {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security session should be created. Security session should be initiated. Security session should be responded. Session should be created. Sessions should be removed. New sessions should be started."];
    
    NSUInteger numberOfRequests = 9;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime + 5;
    
    VSSKeyPair *initiatorKeyPair = [self.crypto generateKeyPair];
    VSSKeyPair *responderKeyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *initiatorIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:initiatorKeyPair];
    VSSCreateCardRequest *responderIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:responderKeyPair];
    
    [self.virgilClient createCardWithRequest:initiatorIdentityRequest completion:^(VSSCard *initiatorCard, NSError *error) {
        [self.virgilClient createCardWithRequest:responderIdentityRequest completion:^(VSSCard *responderCard, NSError *error) {
            sleep(5);
            
            VSPSecureChatPreferences *initiatorPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:initiatorKeyPair.privateKey identityCard:initiatorCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
            
            VSPSecureChatPreferences *responderPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:responderKeyPair.privateKey identityCard:responderCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
            
            self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences];
            self.responderSecureChat = [[VSPSecureChat alloc] initWithPreferences:responderPreferences];
            
            [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
                [self.responderSecureChat initializeWithCompletion:^(NSError * error) {
                    [self.initiatorSecureChat startNewSessionWithRecipientWithCard:responderCard additionalData:nil completion:^(VSPSecureSession *initiatorSession, NSError *error) {
                        NSError *err;
                        
                        NSString *encryptedMessage1 = [initiatorSession encrypt:self.message1 error:&err];
                        XCTAssert(err == nil);
                        
                        BOOL res = [self.initiatorSecureChat removeSessionWithParticipantWithCardId:responderCard.identifier error:&err];
                        XCTAssert(res == YES && err == nil);
                        
                        VSPSecureSession *removedInitiatorSession = [self.initiatorSecureChat activeSessionWithParticipantWithCardId:responderCard.identifier];
                        XCTAssert(removedInitiatorSession == nil);
                        
                        VSPSecureSession *responderSession = [self.responderSecureChat loadUpSessionWithParticipantWithCard:initiatorCard message:encryptedMessage1 additionalData:nil error:&err];
                        XCTAssert(err == nil);
                        XCTAssert(responderSession != nil);
                        NSString *decryptedMessage1 = [responderSession decrypt:encryptedMessage1 error:&err];
                        XCTAssert(err == nil);
                        XCTAssert([self.message1 isEqualToString:decryptedMessage1]);
                        
                        res = [self.responderSecureChat removeSessionWithParticipantWithCardId:initiatorCard.identifier error:&err];
                        XCTAssert(res == YES && err == nil);
                        
                        VSPSecureSession *removedResponderSession = [self.initiatorSecureChat activeSessionWithParticipantWithCardId:initiatorCard.identifier];
                        XCTAssert(removedResponderSession == nil);
                        
                        [self.initiatorSecureChat startNewSessionWithRecipientWithCard:responderCard additionalData:nil completion:^(VSPSecureSession *recreatedInitiatorSession, NSError *error) {
                            XCTAssert(error == nil && recreatedInitiatorSession != nil);
                            
                            NSError *err;
                            
                            NSString *encryptedMessage1 = [recreatedInitiatorSession encrypt:self.message1 error:&err];
                            XCTAssert(err == nil);
                            
                            VSPSecureSession *recreatedResponderSession = [self.responderSecureChat loadUpSessionWithParticipantWithCard:initiatorCard message:encryptedMessage1 additionalData:nil error:&err];
                            XCTAssert(err == nil && recreatedResponderSession != nil);
                            NSString *decryptedMessage1 = [recreatedResponderSession decrypt:encryptedMessage1 error:&err];
                            XCTAssert(err == nil);
                            XCTAssert([self.message1 isEqualToString:decryptedMessage1]);
                            
                            [ex fulfill];
                        }];
                    }];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test016_RestartInvalidSession {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security session should be created. Another session with same participant should be started."];
    
    NSUInteger numberOfRequests = 4;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime + 5;
    
    VSSKeyPair *keyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *identityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:keyPair];
    
    [self.virgilClient createCardWithRequest:identityRequest completion:^(VSSCard *card, NSError *error) {
        sleep(5);
        
        VSPSecureChatPreferences *preferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:keyPair.privateKey identityCard:card keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
        
        self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:preferences];
        
        [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
            [self.initiatorSecureChat  startNewSessionWithRecipientWithCard:card additionalData:nil completion:^(VSPSecureSession *session, NSError *error) {
                XCTAssert(error == nil);
                XCTAssert(session != nil);
                
                NSError *err;
                BOOL res = [self.initiatorSecureChat removeSessionWithParticipantWithCardId:card.identifier error:&err];
                XCTAssert(res && err == nil);
                
                [self.initiatorSecureChat  startNewSessionWithRecipientWithCard:card additionalData:nil completion:^(VSPSecureSession *session, NSError *error) {
                    XCTAssert(error == nil);
                    XCTAssert(session != nil);
                    [ex fulfill];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test017_SecureChatDoubleInitialization {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. SecurityChat should be initialized. SecurityChat should be reinitialized."];
    
    NSUInteger numberOfRequests = 3;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime + 5;
    
    VSSKeyPair *keyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *identityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:keyPair];
    
    [self.virgilClient createCardWithRequest:identityRequest completion:^(VSSCard *card, NSError *error) {
        sleep(5);
        
        VSPSecureChatPreferences *preferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:keyPair.privateKey identityCard:card keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:nil];
        
        self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:preferences];
        
        [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
            XCTAssert(error == nil);
            
            self.initiatorSecureChat2 = [[VSPSecureChat alloc] initWithPreferences:preferences];
            
            [self.initiatorSecureChat2 initializeWithCompletion:^(NSError *error) {
                XCTAssert(error == nil);
                
                [ex fulfill];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test018_SecureSessionTimeExpiration {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security session should be created. Security session should be initiated. Security session should be responded. Session should be created. Further encryption/decryption should work."];
    
    NSUInteger numberOfRequests = 8;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime + 5 + 10;
    
    VSSKeyPair *initiatorKeyPair = [self.crypto generateKeyPair];
    VSSKeyPair *responderKeyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *initiatorIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:initiatorKeyPair];
    VSSCreateCardRequest *responderIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:responderKeyPair];
    
    [self.virgilClient createCardWithRequest:initiatorIdentityRequest completion:^(VSSCard *initiatorCard, NSError *error) {
        [self.virgilClient createCardWithRequest:responderIdentityRequest completion:^(VSSCard *responderCard, NSError *error) {
            sleep(5);
            
            VSPSecureChatPreferences *initiatorPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:initiatorKeyPair.privateKey identityCard:initiatorCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:[[NSNumber alloc] initWithDouble:5]];
            
            VSPSecureChatPreferences *responderPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:responderKeyPair.privateKey identityCard:responderCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:[[NSNumber alloc] initWithDouble:5]];
            
            self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences];
            self.responderSecureChat = [[VSPSecureChat alloc] initWithPreferences:responderPreferences];
            
            [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
                [self.responderSecureChat initializeWithCompletion:^(NSError * error) {
                    [self.initiatorSecureChat startNewSessionWithRecipientWithCard:responderCard additionalData:nil completion:^(VSPSecureSession *initiatorSession, NSError *error) {
                        NSString *encryptedMessage1 = [initiatorSession encrypt:self.message1 error:nil];
                        
                        NSError *err;
                        VSPSecureSession *responderSession = [self.responderSecureChat loadUpSessionWithParticipantWithCard:initiatorCard message:encryptedMessage1 additionalData:nil error:&err];
                        XCTAssert(err == nil);
                        XCTAssert(responderSession != nil);
                        NSString *decryptedMessage1 = [responderSession decrypt:encryptedMessage1 error:&err];
                        XCTAssert(err == nil);
                        XCTAssert([self.message1 isEqualToString:decryptedMessage1]);
                        
                        NSString *encryptedMessage2 = [initiatorSession encrypt:self.message2 error:&err];
                        XCTAssert(err == nil);
                        
                        sleep(10);
                        
                        XCTAssert(responderSession.isExpired == YES);
                        XCTAssert(initiatorSession.isExpired == YES);
                        XCTAssert([self.initiatorSecureChat activeSessionWithParticipantWithCardId:responderCard.identifier] == nil);
                        
                        VSPSecureSession *responderSession2 = [self.responderSecureChat loadUpSessionWithParticipantWithCard:initiatorCard message:encryptedMessage2 additionalData:nil error:&err];
                        XCTAssert(err == nil);
                        XCTAssert(responderSession2 != nil);
                        XCTAssert(responderSession2.isExpired == YES);
                        
                        NSString *message2 = [responderSession2 decrypt:encryptedMessage2 error:&err];
                        XCTAssert(err == nil);
                        XCTAssert([self.message2 isEqualToString:message2]);
                        
                        [ex fulfill];
                    }];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test019_RecreateExpiredSession {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security session should be created. Security session should be expired. New session should be created."];
    
    NSUInteger numberOfRequests = 9;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime + 5 + 10;
    
    VSSKeyPair *initiatorKeyPair = [self.crypto generateKeyPair];
    VSSKeyPair *responderKeyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *initiatorIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:initiatorKeyPair];
    VSSCreateCardRequest *responderIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:responderKeyPair];
    
    [self.virgilClient createCardWithRequest:initiatorIdentityRequest completion:^(VSSCard *initiatorCard, NSError *error) {
        [self.virgilClient createCardWithRequest:responderIdentityRequest completion:^(VSSCard *responderCard, NSError *error) {
            sleep(5);
            
            VSPSecureChatPreferences *initiatorPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:initiatorKeyPair.privateKey identityCard:initiatorCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:[[NSNumber alloc] initWithDouble:5]];
            
            VSPSecureChatPreferences *responderPreferences = [VSPSecureChatPreferences secureChatPreferencesWithCrypto:self.crypto privateKey:responderKeyPair.privateKey identityCard:responderCard keyStorage:nil deviceManager:nil serviceConfig:self.client.serviceConfig numberOfActiveOneTimeCards:nil longTermKeysTtl:nil sessionTtl:[[NSNumber alloc] initWithDouble:5]];
            
            self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences];
            self.responderSecureChat = [[VSPSecureChat alloc] initWithPreferences:responderPreferences];
            
            [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
                [self.responderSecureChat initializeWithCompletion:^(NSError * error) {
                    [self.initiatorSecureChat startNewSessionWithRecipientWithCard:responderCard additionalData:nil completion:^(VSPSecureSession *initiatorSession, NSError *error) {
                        NSString *encryptedMessage1 = [initiatorSession encrypt:self.message1 error:nil];
                        
                        NSError *err;
                        VSPSecureSession *responderSession = [self.responderSecureChat loadUpSessionWithParticipantWithCard:initiatorCard message:encryptedMessage1 additionalData:nil error:&err];
                        XCTAssert(err == nil);
                        XCTAssert(responderSession != nil);
                        NSString *decryptedMessage1 = [responderSession decrypt:encryptedMessage1 error:&err];
                        XCTAssert(err == nil);
                        XCTAssert([self.message1 isEqualToString:decryptedMessage1]);
                        
                        sleep(10);
                        
                        [self.initiatorSecureChat startNewSessionWithRecipientWithCard:responderCard additionalData:nil completion:^(VSPSecureSession *initiatorSession2, NSError *error) {
                            XCTAssert(initiatorSession2 != nil && error == nil);
                            NSError *err;
                            NSString *encryptedMessage2 = [initiatorSession2 encrypt:self.message2 error:&err];
                            VSPSecureSession *responderSession2 = [self.responderSecureChat loadUpSessionWithParticipantWithCard:initiatorCard message:encryptedMessage2 additionalData:nil error:&err];
                            XCTAssert(err == nil);
                            XCTAssert(responderSession2 != nil);
                            
                            NSString *message2 = [responderSession2 decrypt:encryptedMessage2 error:&err];
                            XCTAssert(err == nil);
                            XCTAssert([self.message2 isEqualToString:message2]);
                            
                            [ex fulfill];
                        }];
                    }];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

@end
