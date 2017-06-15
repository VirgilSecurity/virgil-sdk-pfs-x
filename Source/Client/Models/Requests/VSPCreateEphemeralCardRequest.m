//
//  VSPCreateEphemeralCardRequest.m
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 6/15/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSPCreateEphemeralCardRequest.h"

@implementation VSPCreateEphemeralCardRequest

+ (instancetype)createEphemeralCardRequestWithIdentity:(NSString *)identity identityType:(NSString *)identityType publicKeyData:(NSData *)publicKeyData data:(NSDictionary<NSString *, NSString *> *)data {
    VSSCreateCardSnapshotModel *model = [[VSSCreateCardSnapshotModel alloc] initWithIdentity:identity identityType:identityType scope:VSSCardScopeApplication publicKeyData:publicKeyData data:data info:nil];
    
    return [[VSPCreateEphemeralCardRequest alloc] initWithSnapshotModel:model];
}

+ (instancetype)createEphemeralCardRequestWithIdentity:(NSString *)identity identityType:(NSString *)identityType publicKeyData:(NSData *)publicKeyData data:(NSDictionary<NSString *, NSString *> *)data device:(NSString *)device deviceName:(NSString *)deviceName {
    NSDictionary *info = @{
                           kVSSCModelDevice: [device copy],
                           kVSSCModelDeviceName: [deviceName copy]
                           };
    
    VSSCreateCardSnapshotModel *model = [[VSSCreateCardSnapshotModel alloc] initWithIdentity:identity identityType:identityType scope:VSSCardScopeApplication publicKeyData:publicKeyData data:data info:info];
    
    return [[VSPCreateEphemeralCardRequest alloc] initWithSnapshotModel:model];
}

+ (instancetype)createEphemeralCardRequestWithIdentity:(NSString *)identity identityType:(NSString *)identityType publicKeyData:(NSData *)publicKeyData {
    return [VSPCreateEphemeralCardRequest createEphemeralCardRequestWithIdentity:identity identityType:identityType publicKeyData:publicKeyData data:nil];
}


@end
