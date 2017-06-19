//
//  VirgilSDKPFS_iOS_Tests.m
//  VirgilSDKPFS iOS Tests
//
//  Created by Oleksandr Deundiak on 6/16/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "VSPTestsConst.h"
#import "VSPTestUtils.h"
@import VirgilSDK;
@import VirgilSDKPFS;

static const NSTimeInterval kEstimatedRequestCompletionTime = 8.;

@interface VirgilSDKPFS_iOS_Tests : XCTestCase

@property (nonatomic) VSSClient *virgilClient;
@property (nonatomic) VSPClient *client;
@property (nonatomic) id<VSSCrypto> crypto;
@property (nonatomic) VSPTestsConst *consts;
@property (nonatomic) VSPTestUtils *utils;

@end

@implementation VirgilSDKPFS_iOS_Tests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
    
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
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)test001_CreateEntry {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Entry should be created"];
    
    NSUInteger numberOfRequests = 2;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime;
    
    VSSKeyPair *keyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *identityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:keyPair];
    
    [self.virgilClient createCardWithRequest:identityRequest completion:^(VSSCard *card, NSError *error) {
        XCTAssert(error == nil);
    
        VSPCreateEphemeralCardRequest *longTermCardRequest = [self.utils instantiateEphemeralCreateCardRequestsWithKeyPair:nil ltc:YES identityCardId:card.identifier identityPrivateKey:keyPair.privateKey];
        
        NSUInteger numberOfCards = 50;
        NSArray<VSPCreateEphemeralCardRequest *> *oneTimeCards = [self.utils instantiateMultipleEphemeralCreateCardRequestsForNumber:numberOfCards identityCardId:card.identifier identityPrivateKey:keyPair.privateKey];
        
        [self.client createEntryForRecipientWithCardId:card.identifier longTermCardRequest:longTermCardRequest oneTimeCardsRequests:oneTimeCards completion:^(VSSCard *longTermCard, NSArray<VSSCard *> *oneTimeCards, NSError * error) {
            XCTAssert(error == nil);
            XCTAssert(longTermCardRequest != nil);
            XCTAssert(oneTimeCards != nil);
            XCTAssert(oneTimeCards.count == numberOfCards);
            
            for (int i = 0; i < oneTimeCards.count; i++) {
                XCTAssert(oneTimeCards[i] != nil);
            }
            
            [ex fulfill];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test002_CreateLongTermCard {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Long-term card should be created"];
    
    NSUInteger numberOfRequests = 2;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime;
    
    VSSKeyPair *keyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *identityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:keyPair];
    
    [self.virgilClient createCardWithRequest:identityRequest completion:^(VSSCard *card, NSError *error) {
        XCTAssert(error == nil);
        
        VSPCreateEphemeralCardRequest *longTermCardRequest = [self.utils instantiateEphemeralCreateCardRequestsWithKeyPair:nil ltc:YES identityCardId:card.identifier identityPrivateKey:keyPair.privateKey];
        
        [self.client createLongTermCardForRecipientWithCardId:card.identifier longTermCardRequest:longTermCardRequest completion:^(VSSCard *longTermCard, NSError *error) {
            XCTAssert(error == nil);
            XCTAssert(longTermCardRequest != nil);
            
            [ex fulfill];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test003_CreateOneTimeCards {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. One-time cards should be created"];
    
    NSUInteger numberOfRequests = 2;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime;
    
    VSSKeyPair *keyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *identityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:keyPair];
    
    [self.virgilClient createCardWithRequest:identityRequest completion:^(VSSCard *card, NSError *error) {
        XCTAssert(error == nil);
        
        NSUInteger numberOfCards = 50;
        NSArray<VSPCreateEphemeralCardRequest *> *oneTimeCards = [self.utils instantiateMultipleEphemeralCreateCardRequestsForNumber:numberOfCards identityCardId:card.identifier identityPrivateKey:keyPair.privateKey];
        
        [self.client createOneTimeCardsForRecipientWithCardId:card.identifier oneTimeCardsRequests:oneTimeCards completion:^(NSArray<VSSCard *> *oneTimeCards, NSError * error) {
            XCTAssert(error == nil);
            XCTAssert(oneTimeCards != nil);
            XCTAssert(oneTimeCards.count == numberOfCards);
            
            for (int i = 0; i < oneTimeCards.count; i++) {
                XCTAssert(oneTimeCards[i] != nil);
            }
            
            [ex fulfill];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test004_CreateEntry {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Entry should be created"];
    
    NSUInteger numberOfRequests = 2;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime;
    
    VSSKeyPair *keyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *identityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:keyPair];
    
//    self.client 
    
    [self.virgilClient createCardWithRequest:identityRequest completion:^(VSSCard *card, NSError *error) {
        XCTAssert(error == nil);
        
        VSPCreateEphemeralCardRequest *longTermCardRequest = [self.utils instantiateEphemeralCreateCardRequestsWithKeyPair:nil ltc:YES identityCardId:card.identifier identityPrivateKey:keyPair.privateKey];
        
        NSUInteger numberOfCards = 100;
        NSArray<VSPCreateEphemeralCardRequest *> *oneTimeCards = [self.utils instantiateMultipleEphemeralCreateCardRequestsForNumber:numberOfCards identityCardId:card.identifier identityPrivateKey:keyPair.privateKey];
        
        [self.client createEntryForRecipientWithCardId:card.identifier longTermCardRequest:longTermCardRequest oneTimeCardsRequests:oneTimeCards completion:^(VSSCard *longTermCard, NSArray<VSSCard *> *oneTimeCards, NSError * error) {
            XCTAssert(error == nil);
            XCTAssert(longTermCardRequest != nil);
            XCTAssert(oneTimeCards != nil);
            XCTAssert(oneTimeCards.count == numberOfCards);
            
            for (int i = 0; i < oneTimeCards.count; i++) {
                XCTAssert(oneTimeCards[i] != nil);
            }
            
            [ex fulfill];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

@end
