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
@property (nonatomic) VSPSecureChat *responderSecureChat;
@property (nonatomic) VSSClient *virgilClient;
@property (nonatomic) VSPClient *client;
@property (nonatomic) id<VSSCrypto> crypto;
@property (nonatomic) VSPTestsConst *consts;
@property (nonatomic) VSPTestUtils *utils;
@property (nonatomic) NSUInteger numberOfCards;
@property (nonatomic) NSUInteger daysLongTermLives;
@property (nonatomic) NSUInteger daysSessionLives;
@property (nonatomic) NSString *message1;
@property (nonatomic) NSString *message2;
@property (nonatomic) NSString *message3;
@property (nonatomic) NSString *message4;

@end

@implementation VSP002_SecureChatTests

- (void)setUp {
    [super setUp];
    self.consts = [[VSPTestsConst alloc] init];
    self.utils = [[VSPTestUtils alloc] init];
    self.crypto = [[VSSCrypto alloc] init];
    
    VSSServiceConfig *virgilConfig = [VSSServiceConfig serviceConfigWithToken:self.consts.applicationToken];
    
    VSSCardValidator *validator = [[VSSCardValidator alloc] initWithCrypto:self.crypto];
    VSSPrivateKey *privateKey = [self.crypto importPrivateKeyFromData:[[NSData alloc] initWithBase64EncodedString:self.consts.applicationPrivateKeyBase64 options:0]  withPassword:self.consts.applicationPrivateKeyPassword];
    VSSPublicKey *publicKey = [self.crypto extractPublicKeyFromPrivateKey:privateKey];
    NSData *publicKeyData = [self.crypto exportPublicKey:publicKey];
    XCTAssert([validator addVerifierWithId:self.consts.applicationId publicKeyData:publicKeyData]);
    validator.useVirgilServiceVerifiers = NO;
    virgilConfig.cardValidator = validator;
    
    virgilConfig.cardsServiceURL = self.consts.cardsServiceURL;
    virgilConfig.cardsServiceROURL = self.consts.cardsServiceROURL;
    virgilConfig.registrationAuthorityURL = self.consts.registrationAuthorityURL;
    
    self.virgilClient = [[VSSClient alloc] initWithServiceConfig:virgilConfig];
    
    VSPServiceConfig *config = [[VSPServiceConfig alloc] initWithToken:self.consts.applicationToken ephemeralServiceURL:self.consts.pfsServiceURL];
    self.client = [[VSPClient alloc] initWithServiceConfig:config];
    
    self.numberOfCards = 5;
    self.daysLongTermLives = 7;
    self.daysSessionLives = 3;
    
    self.message1 = @"message1";
    self.message2 = @"message2";
    self.message3 = @"message3";
    self.message4 = @"message4";
}

- (void)tearDown {
    [super tearDown];
}

- (void)test001_CreateAndInitializeSecureChat {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security talk should be created"];
    
    NSUInteger numberOfRequests = 3;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime;
    
    VSSKeyPair *keyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *identityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:keyPair];
    
    [self.virgilClient createCardWithRequest:identityRequest completion:^(VSSCard *card, NSError *error) {
        sleep(5);
        
        VSPSecureChatPreferences *preferences = [[VSPSecureChatPreferences alloc] initWithMyCardId:card.identifier myPrivateKey:keyPair.privateKey crypto:self.crypto keyStorage:[[VSSKeyStorage alloc] init] serviceConfig:self.client.serviceConfig virgilServiceConfig:self.virgilClient.serviceConfig deviceManager:[[VSSDeviceManager alloc] init] numberOfActiveOneTimeCards:self.numberOfCards daysLongTermCardLives:self.daysLongTermLives daysSessionLives:self.daysSessionLives];
        
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

- (void)test002_InitiateTalk {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security talk should be created. Security talk should be initiated."];
    
    NSUInteger numberOfRequests = 4;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime;
    
    VSSKeyPair *keyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *identityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:keyPair];
    
    [self.virgilClient createCardWithRequest:identityRequest completion:^(VSSCard *card, NSError *error) {
        sleep(5);
        
        VSPSecureChatPreferences *preferences = [[VSPSecureChatPreferences alloc] initWithMyCardId:card.identifier myPrivateKey:keyPair.privateKey crypto:self.crypto keyStorage:[[VSSKeyStorage alloc] init] serviceConfig:self.client.serviceConfig virgilServiceConfig:self.virgilClient.serviceConfig deviceManager:[[VSSDeviceManager alloc] init] numberOfActiveOneTimeCards:self.numberOfCards daysLongTermCardLives:self.daysLongTermLives daysSessionLives:self.daysSessionLives];
        
        self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:preferences];
        
        [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
            [self.initiatorSecureChat initiateTalkWithRecipientWithCardId:card.identifier additionalData:nil completion:^(VSPSecureTalk *talk, NSError *error) {
                XCTAssert(error == nil);
                XCTAssert(talk != nil);
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
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security talk should be created. Security talk should be initiated. Security talk should be responded. Session should be created."];
    
    NSUInteger numberOfRequests = 8;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime;
    
    VSSKeyPair *initiatorKeyPair = [self.crypto generateKeyPair];
    VSSKeyPair *responderKeyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *initiatorIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:initiatorKeyPair];
    VSSCreateCardRequest *responderIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:responderKeyPair];
    
    [self.virgilClient createCardWithRequest:initiatorIdentityRequest completion:^(VSSCard *initiatorCard, NSError *error) {
        [self.virgilClient createCardWithRequest:responderIdentityRequest completion:^(VSSCard *responderCard, NSError *error) {
            sleep(5);
            
            VSPSecureChatPreferences *initiatorPreferences = [[VSPSecureChatPreferences alloc] initWithMyCardId:initiatorCard.identifier myPrivateKey:initiatorKeyPair.privateKey crypto:self.crypto keyStorage:[[VSSKeyStorage alloc] init] serviceConfig:self.client.serviceConfig virgilServiceConfig:self.virgilClient.serviceConfig deviceManager:[[VSSDeviceManager alloc] init] numberOfActiveOneTimeCards:self.numberOfCards daysLongTermCardLives:self.daysLongTermLives daysSessionLives:self.daysSessionLives];
            
            VSPSecureChatPreferences *responderPreferences = [[VSPSecureChatPreferences alloc] initWithMyCardId:responderCard.identifier myPrivateKey:responderKeyPair.privateKey crypto:self.crypto keyStorage:[[VSSKeyStorage alloc] init] serviceConfig:self.client.serviceConfig virgilServiceConfig:self.virgilClient.serviceConfig deviceManager:[[VSSDeviceManager alloc] init] numberOfActiveOneTimeCards:self.numberOfCards daysLongTermCardLives:self.daysLongTermLives daysSessionLives:self.daysSessionLives];
            
            self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences];
            self.responderSecureChat = [[VSPSecureChat alloc] initWithPreferences:responderPreferences];
            
            [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
                [self.responderSecureChat initializeWithCompletion:^(NSError * error) {
                    [self.initiatorSecureChat initiateTalkWithRecipientWithCardId:responderCard.identifier additionalData:nil completion:^(VSPSecureTalk *initiatorTalk, NSError *error) {
                        NSError *err;
                        NSData *encryptedMessage = [initiatorTalk encrypt:self.message1 error:&err];
                        XCTAssert(err == nil);
                        XCTAssert(encryptedMessage.length > 0);
                        
                        [self.responderSecureChat respondToTalkWithInitiatorWithCardId:initiatorCard.identifier message:encryptedMessage additionalData:nil completion:^(VSPSecureTalk *responderTalk, NSString *decryptedMessage, NSError *error) {
                            XCTAssert([self.message1 isEqualToString:decryptedMessage]);
                            
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

- (void)test004_SetupSessionEncryptDecrypt {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security talk should be created. Security talk should be initiated. Security talk should be responded. Session should be created. Further encryption/decryption should work."];
    
    NSUInteger numberOfRequests = 8;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime;
    
    VSSKeyPair *initiatorKeyPair = [self.crypto generateKeyPair];
    VSSKeyPair *responderKeyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *initiatorIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:initiatorKeyPair];
    VSSCreateCardRequest *responderIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:responderKeyPair];
    
    [self.virgilClient createCardWithRequest:initiatorIdentityRequest completion:^(VSSCard *initiatorCard, NSError *error) {
        [self.virgilClient createCardWithRequest:responderIdentityRequest completion:^(VSSCard *responderCard, NSError *error) {
            sleep(5);
            
            VSPSecureChatPreferences *initiatorPreferences = [[VSPSecureChatPreferences alloc] initWithMyCardId:initiatorCard.identifier myPrivateKey:initiatorKeyPair.privateKey crypto:self.crypto keyStorage:[[VSSKeyStorage alloc] init] serviceConfig:self.client.serviceConfig virgilServiceConfig:self.virgilClient.serviceConfig deviceManager:[[VSSDeviceManager alloc] init] numberOfActiveOneTimeCards:self.numberOfCards daysLongTermCardLives:self.daysLongTermLives daysSessionLives:self.daysSessionLives];
            
            VSPSecureChatPreferences *responderPreferences = [[VSPSecureChatPreferences alloc] initWithMyCardId:responderCard.identifier myPrivateKey:responderKeyPair.privateKey crypto:self.crypto keyStorage:[[VSSKeyStorage alloc] init] serviceConfig:self.client.serviceConfig virgilServiceConfig:self.virgilClient.serviceConfig deviceManager:[[VSSDeviceManager alloc] init] numberOfActiveOneTimeCards:self.numberOfCards daysLongTermCardLives:self.daysLongTermLives daysSessionLives:self.daysSessionLives];
            
            self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences];
            self.responderSecureChat = [[VSPSecureChat alloc] initWithPreferences:responderPreferences];
            
            [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
                [self.responderSecureChat initializeWithCompletion:^(NSError * error) {
                    [self.initiatorSecureChat initiateTalkWithRecipientWithCardId:responderCard.identifier additionalData:nil completion:^(VSPSecureTalk *initiatorTalk, NSError *error) {
                        NSData *encryptedMessage1 = [initiatorTalk encrypt:self.message1 error:nil];
                        
                        [self.responderSecureChat respondToTalkWithInitiatorWithCardId:initiatorCard.identifier message:encryptedMessage1 additionalData:nil completion:^(VSPSecureTalk *responderTalk, NSString *message1, NSError *error) {
                            XCTAssert([self.message1 isEqualToString:message1]);
                            
                            NSError *err;
                            NSData *encryptedMessage2 = [initiatorTalk encrypt:self.message2 error:&err];
                            NSString *message2 = [responderTalk decrypt:encryptedMessage2 error:&err];
                            XCTAssert(err == nil);
                            XCTAssert([self.message2 isEqualToString:message2]);
                            
                            NSData *encryptedMessage3 = [responderTalk encrypt:self.message3 error:&err];
                            XCTAssert(err == nil);
                            NSString *message3 = [initiatorTalk decrypt:encryptedMessage3 error:&err];
                            XCTAssert(err == nil);
                            XCTAssert([self.message3 isEqualToString:message3]);
                            
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

- (void)test005_RecoverInitiatorSession {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security talk should be created. Security talk should be initiated. Security talk should be responded. Session should be created. Initiator talk should be recovered. Further encryption/decryption should work."];
    
    NSUInteger numberOfRequests = 9;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime;
    
    VSSKeyPair *initiatorKeyPair = [self.crypto generateKeyPair];
    VSSKeyPair *responderKeyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *initiatorIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:initiatorKeyPair];
    VSSCreateCardRequest *responderIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:responderKeyPair];
    
    [self.virgilClient createCardWithRequest:initiatorIdentityRequest completion:^(VSSCard *initiatorCard, NSError *error) {
        [self.virgilClient createCardWithRequest:responderIdentityRequest completion:^(VSSCard *responderCard, NSError *error) {
            sleep(5);
            
            VSPSecureChatPreferences *initiatorPreferences = [[VSPSecureChatPreferences alloc] initWithMyCardId:initiatorCard.identifier myPrivateKey:initiatorKeyPair.privateKey crypto:self.crypto keyStorage:[[VSSKeyStorage alloc] init] serviceConfig:self.client.serviceConfig virgilServiceConfig:self.virgilClient.serviceConfig deviceManager:[[VSSDeviceManager alloc] init] numberOfActiveOneTimeCards:self.numberOfCards daysLongTermCardLives:self.daysLongTermLives daysSessionLives:self.daysSessionLives];
            
            VSPSecureChatPreferences *responderPreferences = [[VSPSecureChatPreferences alloc] initWithMyCardId:responderCard.identifier myPrivateKey:responderKeyPair.privateKey crypto:self.crypto keyStorage:[[VSSKeyStorage alloc] init] serviceConfig:self.client.serviceConfig virgilServiceConfig:self.virgilClient.serviceConfig deviceManager:[[VSSDeviceManager alloc] init] numberOfActiveOneTimeCards:self.numberOfCards daysLongTermCardLives:self.daysLongTermLives daysSessionLives:self.daysSessionLives];
            
            self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences];
            self.responderSecureChat = [[VSPSecureChat alloc] initWithPreferences:responderPreferences];
            
            [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
                [self.responderSecureChat initializeWithCompletion:^(NSError * error) {
                    [self.initiatorSecureChat initiateTalkWithRecipientWithCardId:responderCard.identifier additionalData:nil completion:^(VSPSecureTalk *initiatorTalk, NSError *error) {
                        NSData *encryptedMessage1 = [initiatorTalk encrypt:self.message1 error:nil];
                        
                        [self.responderSecureChat respondToTalkWithInitiatorWithCardId:initiatorCard.identifier message:encryptedMessage1 additionalData:nil completion:^(VSPSecureTalk *responderTalk, NSString *message1, NSError *error) {
                            XCTAssert([self.message1 isEqualToString:message1]);
                            
                            [self.initiatorSecureChat initiateTalkWithRecipientWithCardId:responderCard.identifier additionalData:nil completion:^(VSPSecureTalk *recoveredInitiatorTalk, NSError *error) {
                                XCTAssert(error == nil);
                                XCTAssert(recoveredInitiatorTalk != nil);
                                NSError *err;
                                NSData *encryptedMessage2 = [recoveredInitiatorTalk encrypt:self.message2 error:&err];
                                XCTAssert(err == nil);
                                NSString *message2 = [responderTalk decrypt:encryptedMessage2 error:&err];
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
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test006_RecoverInitiatorSessionWithMessage {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security talk should be created. Security talk should be initiated. Security talk should be responded. Session should be created. Initiator talk should be recovered using message. Further encryption/decryption should work."];
    
    NSUInteger numberOfRequests = 9;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime;
    
    VSSKeyPair *initiatorKeyPair = [self.crypto generateKeyPair];
    VSSKeyPair *responderKeyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *initiatorIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:initiatorKeyPair];
    VSSCreateCardRequest *responderIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:responderKeyPair];
    
    [self.virgilClient createCardWithRequest:initiatorIdentityRequest completion:^(VSSCard *initiatorCard, NSError *error) {
        [self.virgilClient createCardWithRequest:responderIdentityRequest completion:^(VSSCard *responderCard, NSError *error) {
            sleep(5);
            
            VSPSecureChatPreferences *initiatorPreferences = [[VSPSecureChatPreferences alloc] initWithMyCardId:initiatorCard.identifier myPrivateKey:initiatorKeyPair.privateKey crypto:self.crypto keyStorage:[[VSSKeyStorage alloc] init] serviceConfig:self.client.serviceConfig virgilServiceConfig:self.virgilClient.serviceConfig deviceManager:[[VSSDeviceManager alloc] init] numberOfActiveOneTimeCards:self.numberOfCards daysLongTermCardLives:self.daysLongTermLives daysSessionLives:self.daysSessionLives];
            
            VSPSecureChatPreferences *responderPreferences = [[VSPSecureChatPreferences alloc] initWithMyCardId:responderCard.identifier myPrivateKey:responderKeyPair.privateKey crypto:self.crypto keyStorage:[[VSSKeyStorage alloc] init] serviceConfig:self.client.serviceConfig virgilServiceConfig:self.virgilClient.serviceConfig deviceManager:[[VSSDeviceManager alloc] init] numberOfActiveOneTimeCards:self.numberOfCards daysLongTermCardLives:self.daysLongTermLives daysSessionLives:self.daysSessionLives];
            
            self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences];
            self.responderSecureChat = [[VSPSecureChat alloc] initWithPreferences:responderPreferences];
            
            [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
                [self.responderSecureChat initializeWithCompletion:^(NSError * error) {
                    [self.initiatorSecureChat initiateTalkWithRecipientWithCardId:responderCard.identifier additionalData:nil completion:^(VSPSecureTalk *initiatorTalk, NSError *error) {
                        NSData *encryptedMessage1 = [initiatorTalk encrypt:self.message1 error:nil];
                        
                        [self.responderSecureChat respondToTalkWithInitiatorWithCardId:initiatorCard.identifier message:encryptedMessage1 additionalData:nil completion:^(VSPSecureTalk *responderTalk, NSString *message1, NSError *error) {
                            XCTAssert([self.message1 isEqualToString:message1]);
                            NSData *encryptedMessage2 = [responderTalk encrypt:self.message2 error:nil];
                            
                            [self.initiatorSecureChat respondToTalkWithInitiatorWithCardId:responderCard.identifier message:encryptedMessage2 additionalData:nil completion:^(VSPSecureTalk *recoveredInitiatorTalk, NSString *message2, NSError *error) {
                                XCTAssert(error == nil);
                                XCTAssert(recoveredInitiatorTalk != nil);
                                XCTAssert([self.message2 isEqualToString:message2]);
                                
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

- (void)test007_RecoverResponderSession {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security talk should be created. Security talk should be initiated. Security talk should be responded. Session should be created. Responder talk should be recovered. Further encryption/decryption should work."];
    
    NSUInteger numberOfRequests = 9;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime;
    
    VSSKeyPair *initiatorKeyPair = [self.crypto generateKeyPair];
    VSSKeyPair *responderKeyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *initiatorIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:initiatorKeyPair];
    VSSCreateCardRequest *responderIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:responderKeyPair];
    
    [self.virgilClient createCardWithRequest:initiatorIdentityRequest completion:^(VSSCard *initiatorCard, NSError *error) {
        [self.virgilClient createCardWithRequest:responderIdentityRequest completion:^(VSSCard *responderCard, NSError *error) {
            sleep(5);
            
            VSPSecureChatPreferences *initiatorPreferences = [[VSPSecureChatPreferences alloc] initWithMyCardId:initiatorCard.identifier myPrivateKey:initiatorKeyPair.privateKey crypto:self.crypto keyStorage:[[VSSKeyStorage alloc] init] serviceConfig:self.client.serviceConfig virgilServiceConfig:self.virgilClient.serviceConfig deviceManager:[[VSSDeviceManager alloc] init] numberOfActiveOneTimeCards:self.numberOfCards daysLongTermCardLives:self.daysLongTermLives daysSessionLives:self.daysSessionLives];
            
            VSPSecureChatPreferences *responderPreferences = [[VSPSecureChatPreferences alloc] initWithMyCardId:responderCard.identifier myPrivateKey:responderKeyPair.privateKey crypto:self.crypto keyStorage:[[VSSKeyStorage alloc] init] serviceConfig:self.client.serviceConfig virgilServiceConfig:self.virgilClient.serviceConfig deviceManager:[[VSSDeviceManager alloc] init] numberOfActiveOneTimeCards:self.numberOfCards daysLongTermCardLives:self.daysLongTermLives daysSessionLives:self.daysSessionLives];
            
            self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences];
            self.responderSecureChat = [[VSPSecureChat alloc] initWithPreferences:responderPreferences];
            
            [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
                [self.responderSecureChat initializeWithCompletion:^(NSError * error) {
                    [self.initiatorSecureChat initiateTalkWithRecipientWithCardId:responderCard.identifier additionalData:nil completion:^(VSPSecureTalk *initiatorTalk, NSError *error) {
                        NSData *encryptedMessage1 = [initiatorTalk encrypt:self.message1 error:nil];
                        
                        [self.responderSecureChat respondToTalkWithInitiatorWithCardId:initiatorCard.identifier message:encryptedMessage1 additionalData:nil completion:^(VSPSecureTalk *responderTalk, NSString *message1, NSError *error) {
                            XCTAssert([self.message1 isEqualToString:message1]);
                            
                            [self.responderSecureChat initiateTalkWithRecipientWithCardId:initiatorCard.identifier additionalData:nil completion:^(VSPSecureTalk *recoveredResponderTalk, NSError *error) {
                                XCTAssert(error == nil);
                                XCTAssert(recoveredResponderTalk != nil);
                                NSError *err;
                                NSData *encryptedMessage2 = [initiatorTalk encrypt:self.message2 error:&err];
                                XCTAssert(err == nil);
                                NSString *message2 = [recoveredResponderTalk decrypt:encryptedMessage2 error:&err];
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
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test008_RecoverResponderSessionWithMessage {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security talk should be created. Security talk should be initiated. Security talk should be responded. Session should be created. Responder talk should be recovered using message. Further encryption/decryption should work."];
    
    NSUInteger numberOfRequests = 9;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime;
    
    VSSKeyPair *initiatorKeyPair = [self.crypto generateKeyPair];
    VSSKeyPair *responderKeyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *initiatorIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:initiatorKeyPair];
    VSSCreateCardRequest *responderIdentityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:responderKeyPair];
    
    [self.virgilClient createCardWithRequest:initiatorIdentityRequest completion:^(VSSCard *initiatorCard, NSError *error) {
        [self.virgilClient createCardWithRequest:responderIdentityRequest completion:^(VSSCard *responderCard, NSError *error) {
            sleep(5);
            
            VSPSecureChatPreferences *initiatorPreferences = [[VSPSecureChatPreferences alloc] initWithMyCardId:initiatorCard.identifier myPrivateKey:initiatorKeyPair.privateKey crypto:self.crypto keyStorage:[[VSSKeyStorage alloc] init] serviceConfig:self.client.serviceConfig virgilServiceConfig:self.virgilClient.serviceConfig deviceManager:[[VSSDeviceManager alloc] init] numberOfActiveOneTimeCards:self.numberOfCards daysLongTermCardLives:self.daysLongTermLives daysSessionLives:self.daysSessionLives];
            
            VSPSecureChatPreferences *responderPreferences = [[VSPSecureChatPreferences alloc] initWithMyCardId:responderCard.identifier myPrivateKey:responderKeyPair.privateKey crypto:self.crypto keyStorage:[[VSSKeyStorage alloc] init] serviceConfig:self.client.serviceConfig virgilServiceConfig:self.virgilClient.serviceConfig deviceManager:[[VSSDeviceManager alloc] init] numberOfActiveOneTimeCards:self.numberOfCards daysLongTermCardLives:self.daysLongTermLives daysSessionLives:self.daysSessionLives];
            
            self.initiatorSecureChat = [[VSPSecureChat alloc] initWithPreferences:initiatorPreferences];
            self.responderSecureChat = [[VSPSecureChat alloc] initWithPreferences:responderPreferences];
            
            [self.initiatorSecureChat initializeWithCompletion:^(NSError *error) {
                [self.responderSecureChat initializeWithCompletion:^(NSError * error) {
                    [self.initiatorSecureChat initiateTalkWithRecipientWithCardId:responderCard.identifier additionalData:nil completion:^(VSPSecureTalk *initiatorTalk, NSError *error) {
                        NSData *encryptedMessage1 = [initiatorTalk encrypt:self.message1 error:nil];
                        
                        [self.responderSecureChat respondToTalkWithInitiatorWithCardId:initiatorCard.identifier message:encryptedMessage1 additionalData:nil completion:^(VSPSecureTalk *responderTalk, NSString *message1, NSError *error) {
                            XCTAssert([self.message1 isEqualToString:message1]);
                            NSData *encryptedMessage2 = [initiatorTalk encrypt:self.message2 error:nil];
                            
                            [self.responderSecureChat respondToTalkWithInitiatorWithCardId:initiatorCard.identifier message:encryptedMessage2 additionalData:nil completion:^(VSPSecureTalk *recoveredResponderTalk, NSString *message2, NSError *error) {
                                XCTAssert(error == nil);
                                XCTAssert(recoveredResponderTalk != nil);
                                XCTAssert([self.message2 isEqualToString:message2]);
                                
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

@end
