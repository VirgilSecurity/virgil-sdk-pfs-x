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

- (void)test002_PredefinedCards2 {
    NSError *error;
    NSString *fingerprint = [VSPFingerprint calculateFingerprintForCardsIds:@[@"7053f3b4ac89480f3a4c43c1fdb0f09b8154236175b7f55aac9b920d10a4adc7", @"78e75f23163ae7d9568e992b73d77c91d868dbdf91099144bb019859364f698c", @"ebbc9ebcc76c6dd1dd4f44e66b8166e57f630d28b5052a56e651dda033f3dc9d"] error:&error];
    
    XCTAssert(error == nil);
    XCTAssert([fingerprint isEqualToString:@"30040 86431 59747 52666 37436 94430 71043 18723 34794 81546 12838 92218"]);
}

- (void)test003_PerformanceTest {
    [self measureBlock:^{
        NSString * __unused fingerprint = [VSPFingerprint calculateFingerprintForCardsIds:@[@"b", @"c", @"a"] error:nil];
    }];
}

@end
