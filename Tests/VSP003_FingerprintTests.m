//
//  VSP003_FingerprintTests.m
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 7/11/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>
@import VirgilSDK;
@import VirgilSDKPFS;

@interface VSP003_FingerpintTests : XCTestCase

@property (nonatomic) VSSVirgilApi * __nonnull api;

@end

@implementation VSP003_FingerpintTests

- (void)setUp {
    [super setUp];
    
    self.api = [[VSSVirgilApi alloc] init];
}

- (void)tearDown {
    [super tearDown];
}

- (void)test001_RandomCards {
    VSSVirgilIdentity *identity1 = [self.api.Identities createUserIdentityWithValue:[[[NSUUID alloc] init] UUIDString] type:[[[NSUUID alloc] init] UUIDString]];
    VSSVirgilIdentity *identity2 = [self.api.Identities createUserIdentityWithValue:[[[NSUUID alloc] init] UUIDString] type:[[[NSUUID alloc] init] UUIDString]];
    VSSVirgilIdentity *identity3 = [self.api.Identities createUserIdentityWithValue:[[[NSUUID alloc] init] UUIDString] type:[[[NSUUID alloc] init] UUIDString]];
    
    VSSVirgilCard *card1 = [self.api.Cards createCardWithIdentity:identity1 ownerKey:[self.api.Keys generateKey] error:nil];
    VSSVirgilCard *card2 = [self.api.Cards createCardWithIdentity:identity2 ownerKey:[self.api.Keys generateKey] error:nil];
    VSSVirgilCard *card3 = [self.api.Cards createCardWithIdentity:identity3 ownerKey:[self.api.Keys generateKey] error:nil];
    
    NSError *error;
    NSString *fingerprint = [VSPFingerprint calculateFingerprintForCardsIds:@[card1.identifier, card2.identifier, card3.identifier] error:&error];
    
    XCTAssert(error == nil);
    XCTAssert(fingerprint.length > 0);
}

- (void)test002_PredefinedCards {
    NSError *error;
    NSString *fingerprint = [VSPFingerprint calculateFingerprintForCardsIds:@[@"b", @"c", @"a"] error:&error];
    
    XCTAssert(error == nil);
    XCTAssert([fingerprint isEqualToString:@"95767 63932 18392 87777 58010 79361 43185 89666 69268 33576 75875 36436"]);
}

- (void)test003_PerfomanceTest {
    [self measureBlock:^{
        NSString * __unused fingerprint = [VSPFingerprint calculateFingerprintForCardsIds:@[@"b", @"c", @"a"] error:nil];
    }];
}

@end
