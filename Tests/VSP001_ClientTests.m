//
//  VSP001_ClientTests.m
//  VirgilSDKPFS iOS Tests
//
//  Created by Oleksandr Deundiak on 6/16/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "VSPTestsConst.h"
#import "VSPTestUtils.h"
#import "VSPPfsTestUtils.h"
@import VirgilSDK;
@import VirgilSDKPFS;
#import "VSPInternalClientAPI.h"

static const NSTimeInterval kEstimatedRequestCompletionTime = 8.;

@interface VSP001_ClientTests : XCTestCase

@property (nonatomic) VSSClient *virgilClient;
@property (nonatomic) VSPClient *client;
@property (nonatomic) id<VSSCrypto> crypto;
@property (nonatomic) VSPTestsConst *consts;
@property (nonatomic) VSPTestUtils *utils;
@property (nonatomic) VSPPfsTestUtils *pfsUtils;
@property (nonatomic) NSUInteger numberOfCards;

@end

@implementation VSP001_ClientTests

- (void)setUp {
    [super setUp];
    
    self.consts = [[VSPTestsConst alloc] init];
    self.crypto = [[VSSCrypto alloc] init];
    self.utils = [[VSPTestUtils alloc] initWithCrypto:self.crypto consts:self.consts];
    self.pfsUtils = [[VSPPfsTestUtils alloc] initWithCrypto:self.crypto consts:self.consts];
    
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
    
    self.numberOfCards = 100;
}

- (void)tearDown {
    [super tearDown];
}

- (void)test001_CreateEntry {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Entry should be created"];
    
    NSUInteger numberOfRequests = 2;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime;
    
    VSSKeyPair *keyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *identityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:keyPair];
    
    [self.virgilClient createCardWithRequest:identityRequest completion:^(VSSCard *card, NSError *error) {
        VSPCreateEphemeralCardRequest *longTermCardRequest = [self.pfsUtils instantiateEphemeralCreateCardRequestsWithKeyPair:nil identityCardId:card.identifier identityPrivateKey:keyPair.privateKey];
        
        NSArray<VSPCreateEphemeralCardRequest *> *oneTimeCards = [self.pfsUtils instantiateMultipleEphemeralCreateCardRequestsForNumber:self.numberOfCards identityCardId:card.identifier identityPrivateKey:keyPair.privateKey];
        
        [self.client bootstrapCardsSetForUserWithCardId:card.identifier longTermCardRequest:longTermCardRequest oneTimeCardsRequests:oneTimeCards completion:^(VSSCard *longTermCard, NSArray<VSSCard *> *oneTimeCards, NSError * error) {
            XCTAssert(error == nil);
            XCTAssert(longTermCardRequest != nil);
            XCTAssert(oneTimeCards != nil);
            XCTAssert(oneTimeCards.count == self.numberOfCards);
            
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
        VSPCreateEphemeralCardRequest *longTermCardRequest = [self.pfsUtils instantiateEphemeralCreateCardRequestsWithKeyPair:nil identityCardId:card.identifier identityPrivateKey:keyPair.privateKey];
        
        [self.client createLongTermCardForUserWithCardId:card.identifier longTermCardRequest:longTermCardRequest completion:^(VSSCard *longTermCard, NSError *error) {
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
        NSArray<VSPCreateEphemeralCardRequest *> *oneTimeCards = [self.pfsUtils instantiateMultipleEphemeralCreateCardRequestsForNumber:self.numberOfCards identityCardId:card.identifier identityPrivateKey:keyPair.privateKey];
        
        [self.client createOneTimeCardsForUserWithCardId:card.identifier oneTimeCardsRequests:oneTimeCards completion:^(NSArray<VSSCard *> *oneTimeCards, NSError * error) {
            XCTAssert(error == nil);
            XCTAssert(oneTimeCards != nil);
            XCTAssert(oneTimeCards.count == self.numberOfCards);
            
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

- (void)test004_GetCardInfo {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Entry should be created. Cards info should be obtained."];
    
    NSUInteger numberOfRequests = 3;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime;
    
    VSSKeyPair *keyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *identityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:keyPair];
    
    [self.virgilClient createCardWithRequest:identityRequest completion:^(VSSCard *card, NSError *error) {
        VSPCreateEphemeralCardRequest *longTermCardRequest = [self.pfsUtils instantiateEphemeralCreateCardRequestsWithKeyPair:nil identityCardId:card.identifier identityPrivateKey:keyPair.privateKey];
        
        NSArray<VSPCreateEphemeralCardRequest *> *oneTimeCards = [self.pfsUtils instantiateMultipleEphemeralCreateCardRequestsForNumber:self.numberOfCards identityCardId:card.identifier identityPrivateKey:keyPair.privateKey];
        
        [self.client bootstrapCardsSetForUserWithCardId:card.identifier longTermCardRequest:longTermCardRequest oneTimeCardsRequests:oneTimeCards completion:^(VSSCard *longTermCard, NSArray<VSSCard *> *oneTimeCards, NSError * error) {
            
            [self.client getCardsStatusForUserWithCardId:card.identifier completion:^(VSPCardsStatus *cardsInfo, NSError *error) {
                XCTAssert(error == nil);
                XCTAssert(cardsInfo != nil);
                
                XCTAssert(cardsInfo.active == self.numberOfCards);
                
                [ex fulfill];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test005_GetCredentials {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Entry should be created. Credentials should be obtained."];
    
    NSUInteger numberOfRequests = 3;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime;
    
    VSSKeyPair *keyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *identityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:keyPair];
    
    [self.virgilClient createCardWithRequest:identityRequest completion:^(VSSCard *card, NSError *error) {
        VSPCreateEphemeralCardRequest *longTermCardRequest = [self.pfsUtils instantiateEphemeralCreateCardRequestsWithKeyPair:nil identityCardId:card.identifier identityPrivateKey:keyPair.privateKey];
        
        NSArray<VSPCreateEphemeralCardRequest *> *oneTimeCards = [self.pfsUtils instantiateMultipleEphemeralCreateCardRequestsForNumber:self.numberOfCards identityCardId:card.identifier identityPrivateKey:keyPair.privateKey];
        
        [self.client bootstrapCardsSetForUserWithCardId:card.identifier longTermCardRequest:longTermCardRequest oneTimeCardsRequests:oneTimeCards completion:^(VSSCard *longTermCard, NSArray<VSSCard *> *oneTimeCards, NSError * error) {
            [self.client getRecipientCardsSetForCardsIds:@[card.identifier] completion:^(NSArray<VSPRecipientCardsSet*> *credentials, NSError *error) {
                XCTAssert(error == nil);
                XCTAssert(credentials != nil);
                
                XCTAssert(credentials.count == 1);
                
                VSPRecipientCardsSet *cred = credentials[0];
                XCTAssert(cred != nil);
                
                XCTAssert([longTermCard.identifier isEqualToString:cred.longTermCard.identifier]);
                
                BOOL containsCard = NO;
                for (VSSCard *oneTimeCard in oneTimeCards) {
                    if ([oneTimeCard.identifier isEqualToString:cred.oneTimeCard.identifier]) {
                        containsCard = YES;
                        break;
                    }
                }
                XCTAssert(containsCard);
                
                [ex fulfill];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}


- (void)test006_CheckCardsInfoProgress {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Entry should be created. Credentials should be obtained. Cards Info should be updated"];
    
    NSUInteger numberOfRequests = 4;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime;
    
    VSSKeyPair *keyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *identityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:keyPair];
    
    [self.virgilClient createCardWithRequest:identityRequest completion:^(VSSCard *card, NSError *error) {
        VSPCreateEphemeralCardRequest *longTermCardRequest = [self.pfsUtils instantiateEphemeralCreateCardRequestsWithKeyPair:nil identityCardId:card.identifier identityPrivateKey:keyPair.privateKey];
        
        NSArray<VSPCreateEphemeralCardRequest *> *oneTimeCards = [self.pfsUtils instantiateMultipleEphemeralCreateCardRequestsForNumber:self.numberOfCards identityCardId:card.identifier identityPrivateKey:keyPair.privateKey];
        
        [self.client bootstrapCardsSetForUserWithCardId:card.identifier longTermCardRequest:longTermCardRequest oneTimeCardsRequests:oneTimeCards completion:^(VSSCard *longTermCard, NSArray<VSSCard *> *oneTimeCards, NSError * error) {
            [self.client getRecipientCardsSetForCardsIds:@[card.identifier] completion:^(NSArray<VSPRecipientCardsSet *> *credentials, NSError *error) {
                [self.client getCardsStatusForUserWithCardId:card.identifier completion:^(VSPCardsStatus *cardsInfo, NSError *error) {
                    XCTAssert(error == nil);
                    XCTAssert(cardsInfo != nil);
                    
                    XCTAssert(cardsInfo.active == self.numberOfCards - 1);
                    
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

- (void)test007_ValidateOTC {
    XCTestExpectation *ex = [self expectationWithDescription:@"Identity card should be created. Entry should be created. Credentials should be obtained. OTC should be validated."];
    
    NSUInteger numberOfRequests = 4;
    NSTimeInterval timeout = numberOfRequests * kEstimatedRequestCompletionTime;
    
    VSSKeyPair *keyPair = [self.crypto generateKeyPair];
    
    VSSCreateCardRequest *identityRequest = [self.utils instantiateCreateCardRequestWithKeyPair:keyPair];
    
    [self.virgilClient createCardWithRequest:identityRequest completion:^(VSSCard *card, NSError *error) {
        VSPCreateEphemeralCardRequest *longTermCardRequest = [self.pfsUtils instantiateEphemeralCreateCardRequestsWithKeyPair:nil identityCardId:card.identifier identityPrivateKey:keyPair.privateKey];
        
        NSArray<VSPCreateEphemeralCardRequest *> *oneTimeCards = [self.pfsUtils instantiateMultipleEphemeralCreateCardRequestsForNumber:self.numberOfCards identityCardId:card.identifier identityPrivateKey:keyPair.privateKey];
        
        [self.client bootstrapCardsSetForUserWithCardId:card.identifier longTermCardRequest:longTermCardRequest oneTimeCardsRequests:oneTimeCards completion:^(VSSCard *longTermCard, NSArray<VSSCard *> *oneTimeCards, NSError * error) {
            
            NSMutableArray *cardsIds = [[NSMutableArray alloc] init];
            
            for (VSSCard *card in oneTimeCards) {
                [cardsIds addObject:card.identifier];
            }
            
            [self.client getRecipientCardsSetForCardsIds:@[card.identifier] completion:^(NSArray<VSPRecipientCardsSet *> *credentials, NSError *error) {
                [self.client validateOneTimeCardsForRecipientWithId:card.identifier cardsIds:cardsIds completion:^(NSArray<NSString *> *exhaustedCardsIds, NSError *error) {
                    XCTAssert(error == nil);
                    XCTAssert(exhaustedCardsIds.count == 1);
                    XCTAssert([exhaustedCardsIds[0] isEqualToString:credentials[0].oneTimeCard.identifier]);
                    
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

@end
