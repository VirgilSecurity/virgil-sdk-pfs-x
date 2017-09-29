//
//  VSPInternalClientAPI.h
//  VirgilSDKPFS
//
//  Created by Oleksandr Deundiak on 8/30/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

SWIFT_CLASS_NAMED("RecipientCardsSet")
@interface VSPRecipientCardsSet : NSObject
@property (nonatomic, readonly, strong) VSSCard * _Nonnull longTermCard;
@property (nonatomic, readonly, strong) VSSCard * _Nullable oneTimeCard;
- (nonnull instancetype)initWithLongTermCard:(VSSCard * _Nonnull)longTermCard oneTimeCard:(VSSCard * _Nullable)oneTimeCard OBJC_DESIGNATED_INITIALIZER;
- (nonnull instancetype)init SWIFT_UNAVAILABLE;
@end

SWIFT_CLASS_NAMED("ServiceConfig")
@interface VSPServiceConfig : NSObject
@property (nonatomic, readonly, copy) NSString * _Nonnull token;
@property (nonatomic, readonly, copy) NSURL * _Nonnull ephemeralServiceURL;
- (nonnull instancetype)initWithToken:(NSString * _Nonnull)token ephemeralServiceURL:(NSURL * _Nullable)ephemeralServiceURL OBJC_DESIGNATED_INITIALIZER;
- (nonnull instancetype)init SWIFT_UNAVAILABLE;
@end

SWIFT_CLASS_NAMED("CardsStatus")
@interface VSPCardsStatus : NSObject
@property (nonatomic, readonly) NSInteger active;
- (nonnull instancetype)init SWIFT_UNAVAILABLE;
@end

@class VSSHTTPRequest;

SWIFT_CLASS_NAMED("Client")
@interface VSPClient : VSSBaseClient
- (nonnull instancetype)initWithServiceConfig:(VSPServiceConfig * _Nonnull)serviceConfig OBJC_DESIGNATED_INITIALIZER;
- (nonnull instancetype)initWithToken:(NSString * _Nonnull)token;
- (void)send:(VSSHTTPRequest * _Nonnull)request;
- (nonnull instancetype)init SWIFT_UNAVAILABLE;
@end

@class VSPRecipientCardsSet;

@interface VSPClient (SWIFT_EXTENSION(VirgilSDKPFS))
- (void)getRecipientCardsSetForCardsIds:(NSArray<NSString *> * _Nonnull)cardsIds completion:(void (^ _Nonnull)(NSArray<VSPRecipientCardsSet *> * _Nullable, NSError * _Nullable))completion;
@end


@interface VSPClient (SWIFT_EXTENSION(VirgilSDKPFS))
- (void)getCardsStatusForUserWithCardId:(NSString * _Nonnull)cardId completion:(void (^ _Nonnull)(VSPCardsStatus * _Nullable, NSError * _Nullable))completion;
@end


@interface VSPClient (SWIFT_EXTENSION(VirgilSDKPFS))
- (void)validateOneTimeCardsForRecipientWithId:(NSString * _Nonnull)recipientId cardsIds:(NSArray<NSString *> * _Nonnull)cardsIds completion:(void (^ _Nonnull)(NSArray<NSString *> * _Nullable, NSError * _Nullable))completion;
@end

@class VSPCreateEphemeralCardRequest;
@class VSSCard;

@interface VSPClient (SWIFT_EXTENSION(VirgilSDKPFS))
- (void)bootstrapCardsSetForUserWithCardId:(NSString * _Nonnull)cardId longTermCardRequest:(VSPCreateEphemeralCardRequest * _Nonnull)longTermCardRequest oneTimeCardsRequests:(NSArray<VSPCreateEphemeralCardRequest *> * _Nonnull)oneTimeCardsRequests completion:(void (^ _Nonnull)(VSSCard * _Nullable, NSArray<VSSCard *> * _Nullable, NSError * _Nullable))completion;
- (void)createLongTermCardForUserWithCardId:(NSString * _Nonnull)cardId longTermCardRequest:(VSPCreateEphemeralCardRequest * _Nonnull)longTermCardRequest completion:(void (^ _Nonnull)(VSSCard * _Nullable, NSError * _Nullable))completion;
- (void)createOneTimeCardsForUserWithCardId:(NSString * _Nonnull)cardId oneTimeCardsRequests:(NSArray<VSPCreateEphemeralCardRequest *> * _Nonnull)oneTimeCardsRequests completion:(void (^ _Nonnull)(NSArray<VSSCard *> * _Nullable, NSError * _Nullable))completion;
@end
