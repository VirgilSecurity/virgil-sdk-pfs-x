# Virgil SWIFT PFS SDK

[Installation](#installation) | [Initialization](#initialization) | [Chat Example](#chat-example) | [Register Users](#register-users) | [Documentation](#documentation) | [Support](#support)

[Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application.

[Perfect Forward Secrecy](https://developer.virgilsecurity.com/docs/references/perfect-forward-secrecy) (PFS) for Encrypted Communication allows you to protect previously intercepted traffic from being decrypted even if the main Private Key is compromised.

Virgil __SWIFT PFS SDK__ contains dependent Virgil [.NET/C# SDK](https://github.com/VirgilSecurity/virgil-sdk-x/tree/v4) package.


To initialize and use Virgil PFS SDK, you need to have [Developer Account](https://developer.virgilsecurity.com/account/signin).

## Installation

The Virgil PFS is provided as a package.
Carthage is a decentralized dependency manager that builds your dependencies and provides you with binary frameworks.
You can install Carthage with Homebrew using the following command:
```
$ brew update
$ brew install carthage
```
To integrate VirgilSDKPFS into your Xcode project using Carthage, perform following steps:
* Create an empty file with name Cartfile in your project's root folder, that lists the frameworks you’d like to use in your project.
* Add the following line to your Cartfile
```
github "VirgilSecurity/virgil-sdk-pfs-x" "master"
```
* Run carthage update. This will fetch dependencies into a Carthage/Checkouts folder inside your project's folder, then build each one or download a pre-compiled framework.
* On your application targets’ “General” settings tab, in the “Linked Frameworks and Libraries” section, add each framework you want to use from the Carthage/Build folder inside your project's folder.
* On your application targets’ “Build Phases” settings tab, click the “+” icon and choose “New Run Script Phase”. Create a Run Script in which you specify your shell (ex: /bin/sh), add the following contents to the script area below the shell:
```
/usr/local/bin/carthage copy-frameworks
```
and add the paths to the frameworks you want to use under “Input Files”, e.g.:
```
$(SRCROOT)/Carthage/Build/iOS/VirgilCrypto.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilSDK.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilSDKPFS.framework
```

## Initialization

Be sure that you have already registered at the [Dev Portal](https://developer.virgilsecurity.com/account/signin) and created your application.

To initialize the PFS SDK at the __Client Side__, you need only the __Access Token__ created for a client at [Dev Portal](https://developer.virgilsecurity.com/account/signin).
The Access Token helps to authenticate client's requests.

```swift
let virgil = VSSVirgilApi(token: "[YOUR_ACCESS_TOKEN_HERE]")
```

Virgil .NET/C# PFS SDK is suitable only for Client Side. If you need .NET/C# SDK for Server Side, take a look at this [repository](https://github.com/VirgilSecurity/virgil-sdk-x/tree/v4).

In Virgil every user has a **Private Key** and represented with a **Virgil Card (Identity Card)**.

The Virgil Card contains user's Public Key and all information necessary to identify the user.
Click [here](#register-users) to see more details on how to create user's Virgil Card.



## Chat Example

Before chat initialization, every user must have created Virgil Card.
If you have no Virgil Card yet, you can easily create it with our [guide](#register-users).

To begin communicating with PFS technology, every user must run the initialization:

```swift
let secureChatPreferences = SecureChatPreferences (
    crypto: "[CRYPTO]", // (e.g. VSSCrypto())
    identityPrivateKey: bobKey.privateKey,
    identityCard: bobCard.card!,
    accessToken: "[YOUR_ACCESS_TOKEN_HERE]")

self.secureChat = SecureChat(preferences: secureChatPreferences)

try self.secureChat.initialize()

self.secureChat.rotateKeys(desiredNumberOfCards: 100) { error in
    //...
}
```

Then Sender establishes a secure PFS conversation with Receiver, encrypts and sends the message:

```swift
func sendMessage(forReceiver receiver: User, message: String) {
    guard let session = self.chat.activeSession(
        withParticipantWithCardId: receiver.card.identifier) else {
        // start new session with recipient if session wasn't initialized yet
        self.chat.startNewSession(
            withRecipientWithCard: receiver.card) { session, error in

            guard error == nil, let session = session else {
                // Error handling
                return
            }

            // get an active session by recipient's card id
            self.sendMessage(forReceiver: receiver,
                usingSession: session, message: message)
        }
        return
    }

    self.sendMessage(forReceiver: receiver,
        usingSession: session, message: message)
}

func sendMessage(forReceiver receiver: User,
    usingSession session: SecureSession, message: String) {
    let ciphertext: String
    do {
        // encrypt the message using previously initialized session
        ciphertext = try session.encrypt(message)
    }
    catch {
        // Error handling
        return
    }

    // send a cipher message to recipient using your messaging service
    self.messenger.sendMessage(
        forReceiverWithName: receiver.name, text: ciphertext)
}
```

Receiver decrypts the incoming message using the conversation he has just created:

```swift
func messageReceived(fromSenderWithName senderName: String, message: String) {
    guard let sender = self.users.first(where: { $0.name == senderName }) else {
        // User not found
        return
    }

    self.receiveMessage(fromSender: sender, message: message)
}

func receiveMessage(fromSender sender: User, message: String) {
    do {
        let session = try self.chat.loadUpSession(
            withParticipantWithCard: sender.card, message: message)

        // decrypt message using established session
        let plaintext = try session.decrypt(message)

        // show a message to the user
        print(plaintext)
    }
    catch {
        // Error handling
    }
}
```

With the open session, which works in both directions, Sender and Receiver can continue PFS-encrypted communication.

__Next:__ Take a look at our [Get Started](/docs/get-started/pfs-encrypted-communication.md) guide to see the whole scenario of the PFS-encrypted communication.


## Register Users

In Virgil every user has a **Private Key** and represented with a **Virgil Card (Identity Card)**.

Using Identity Cards, we generate special Cards that have their own life-time:
* **One-time Card (OTC)**
* **Long-time Card (LTC)**

For each session you can use new OTC and delete it after session is finished.

To create user's Identity Virgil Cards, use the following code:

```cs
// generate a new Virgil Key for Alice
let aliceKey = virgil.keys.generateKey()

// save the Alice's Virgil Key into the storage at her device
try! aliceKey.store(withName: @"[KEY_NAME]",
  password: @"[KEY_PASSWORD]")

// create Alice's Virgil Card
var aliceCard = try! virgil.cards.
  createCard(with: aliceIdentity, ownerKey:aliceKey)

// export a Virgil Card to string
let exportedCard = aliceCard.exportData()
```
after Virgil Card creation it is necessary to sign and publish it with Application Private Virgil Key at the server side.

```cs
// import Alice's Virgil Card from string
aliceCard = virgil.cards.importVirgilCard(fromData: cardData)!

// publish the Virgil Card at Virgil Services
virgil.cards.publish(importedCard) { error in
    //...
}
```
Now, you have user's Virgil Cards and ready to initialize a PFS Chat. During initialization you create OTC and LTC Cards.

Find more examples in our [guide](/docs/get-started/pfs-encrypted-communication.md).

## Documentation

Virgil Security has a powerful set of APIs and the documentation to help you get started:

* [Get Started]()
  * [PFS Encrypted Сommunication](/docs/get-started/pfs-encrypted-communication.md)
* [Configuration](/docs/guides/configuration)
  * [Set Up PFS Client Side](/docs/guides/configuration/client-pfs.md)
  * [Set Up Server Side](/docs/guides/configuration/server.md)

To find more examples how to use Virgil Cards, take a look at [.NET SDK documentation](https://github.com/VirgilSecurity/virgil-sdk-x/blob/v4/README.md)

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support

Our developer support team is here to help you. You can find us on [Twitter](https://twitter.com/virgilsecurity) and [email][support].

[support]: mailto:support@virgilsecurity.com
