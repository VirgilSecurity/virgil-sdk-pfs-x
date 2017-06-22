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

@property (nonatomic) VSPSecureChat *secureChat;
@property (nonatomic) VSSClient *virgilClient;
@property (nonatomic) VSPClient *client;
@property (nonatomic) id<VSSCrypto> crypto;
@property (nonatomic) VSPTestsConst *consts;
@property (nonatomic) VSPTestUtils *utils;
@property (nonatomic) NSUInteger numberOfCards;

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
}

- (void)tearDown {
    [super tearDown];
}

- (void)test001_CreateSecureChat {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Security talk should be created"];
    
    NSUInteger numberOfRequests = 2;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime + 200;
    
    VSSKeyPair *keyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *identityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:keyPair];
    
    [self.virgilClient createCardWithRequest:identityRequest completion:^(VSSCard *card, NSError *error) {
        sleep(5);
        
        VSPSecureChatPreferences *preferences = [[VSPSecureChatPreferences alloc] initWithMyCardId:card.identifier myPrivateKey:keyPair.privateKey crypto:self.crypto keyStorage:[[VSSKeyStorage alloc] init] serviceConfig:self.client.serviceConfig virgilServiceConfig:self.virgilClient.serviceConfig numberOfActiveOneTimeCards:self.numberOfCards deviceManager:[[VSSDeviceManager alloc] init]];
        
        self.secureChat = [[VSPSecureChat alloc] initWithPreferences:preferences];
        
        [self.secureChat initializeWithCompletion:^(NSError *error) {
            XCTAssert(error == nil);
            
            [ex fulfill];
        }];
    }];
        
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

@end
