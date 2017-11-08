# Encrypted Communication

 [Set Up Server](#head1) | [Set Up Clients](#head2) | [Register Users](#head3) | [Initialize PFS Chat](#head4) | [Send & Receive Message](#head5)

Virgil Perfect Forward Secrecy (PFS) is designed to prevent any possibility to compromise long-term secret key from affecting the confidentiality of past communications.
In this tutorial, we are helping two people or IoT devices to communicate with full (end-to-end) **encryption** with PFS enabled.


## <a name="head1"></a> Set Up Server
Your server should be able to authorize your users, store Application's Virgil Key and use **Virgil SDK** for cryptographic operations or for some requests to Virgil Services.

SWIFT is not supported on the server side. We recommend you to use one of the next SDKs:
* [RUBY](https://github.com/VirgilSecurity/virgil-sdk-ruby/tree/v4)
* [PHP](https://github.com/VirgilSecurity/virgil-sdk-php/tree/v4)
* [GO](https://github.com/VirgilSecurity/virgil-crypto-go/tree/v4)
* [JAVASCRIPT](https://github.com/VirgilSecurity/virgil-sdk-javascript/tree/v4)
* [JAVA](https://github.com/VirgilSecurity/virgil-sdk-java-android/tree/v4)
* [PYTHON](https://github.com/VirgilSecurity/virgil-sdk-python/tree/v4)
* [C#/.NET](https://github.com/VirgilSecurity/virgil-sdk-net/tree/v4)


## <a name="head2"></a> Set Up Clients
Set up the client side. After users register at your Application Server, provide them with an access token that authenticates users for further operations and transmit their Virgil Cards to the server. Configure the client side using the [Setup Guide](/docs/swift/guides/configuration/client.md).


## <a name="head3"></a> Register Users
Now you need to register the users who will participate in encrypted communications.

To sign and encrypt a message, each user must have his own tools, which allow him to perform cryptographic operations. These tools must contain the necessary information to identify users. In Virgil Security, such tools are the Virgil Key and the Virgil Card.

![Virgil Card](/docs/swift/img/Card_introduct.png "Create Virgil Card")

When we have already set up the Virgil SDK on the server and client sides, we can finally create Virgil Cards for the users and transmit the Cards to your Server for further publication on Virgil Services.


### Generate Keys and Create Virgil Card
Use the Virgil SDK on the client side to generate a new Key Pair. Then, with recently generated Virgil Key, create user's Virgil Card. All keys are generated and stored on the client side.

In this example, we are passing on the user's username and a password, which will lock in their private encryption key. Each Virgil Card is signed by user's Virgil Key, which guarantees the Virgil Card content integrity over its life cycle.

```swift
// generate a new Virgil Key
let aliceKey = virgil.keys.generateKey()

// save the Virgil Key into storage
try! aliceKey.store(withName: @"[KEY_NAME]",
  password: @"[KEY_PASSWORD]")

// create identity for Alice
let aliceIdentity = virgil.identities.
  createUserIdentity(withValue: "alice", type: "name")

// create a Virgil Card
var aliceCard = try! virgil.cards.
  createCard(with: aliceIdentity, ownerKey:aliceKey)
```


**Warning**: Virgil doesn't keep a copy of your Virgil Key. If you lose a Virgil Key, there is no way to recover it.

**Note**: Recently created users' Virgil Cards are visible only for application users because they are related to the Application.

Read more about Virgil Cards and their types [here](/docs/swift/guides/virgil-card/creating-card.md).


### Transmit the Cards to Your Server

Next, you must serialize and transmit these Cards to your server, where you will approve and publish users' Cards.

```swift
// export a Virgil Card to string
let exportedCard = aliceCard.exportData()

// transmit the Virgil Card to the server and receive response
let cardData = TransmitToServer(exportedCard)

// import Card
aliceCard = virgil.cards.importVirgilCard(fromData: cardData)!
```

SWIFT is not supported for publishing Virgil Cards on Virgil Services.
We recommend using one of the next SDKs:
* [RUBY](https://github.com/VirgilSecurity/virgil-sdk-ruby/tree/v4): [approve & publish users guide](https://github.com/VirgilSecurity/virgil-sdk-ruby/blob/v4/docs/guides/configuration/server.md#-approve--publish-cards)  
* [PHP](https://github.com/VirgilSecurity/virgil-sdk-php/tree/v4): [approve & publish users guide](https://github.com/VirgilSecurity/virgil-sdk-php/blob/v4/docs/guides/configuration/server-configuration.md#-approve--publish-cards)  
* [GO](https://github.com/VirgilSecurity/virgil-crypto-go/tree/v4): [approve & publish users guide](https://github.com/go-virgil/virgil/blob/v4/docs/guides/configuration/server-configuration.md#-approve--publish-cards)  
* [JAVASCRIPT](https://github.com/VirgilSecurity/virgil-sdk-javascript/tree/v4): [approve & publish users guide](https://github.com/VirgilSecurity/virgil-sdk-javascript/blob/v4/docs/guides/configuration/server.md#-approve--publish-cards)  
* [JAVA](https://github.com/VirgilSecurity/virgil-sdk-java-android/tree/v4): [approve & publish users guide](https://github.com/VirgilSecurity/virgil-sdk-java-android/blob/v4/docs/guides/configuration/server-configuration.md#-approve--publish-cards)  
* [PYTHON](https://github.com/VirgilSecurity/virgil-sdk-python/tree/v4): [approve & publish users guide](https://github.com/VirgilSecurity/virgil-sdk-python/blob/v4/documentation/guides/configuration/server.md#-approve--publish-cards)  
* [C#/.NET](https://github.com/VirgilSecurity/virgil-sdk-net/tree/v4): [approve & publish users guide](https://github.com/VirgilSecurity/virgil-sdk-net/blob/v4/documentation/guides/configuration/server.md#-approve--publish-cards)  




## <a name="head4"></a> Initialize PFS Chat

With the user's Cards in place, we are now ready to initialize a PFS chat. In this case, we will use the Recipient's Private Keys, the Virgil Cards and the Access Token.
In order to begin communicating, Bob must run the initialization:

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

Then, Alice must run the initialization:

```swift
let secureChatPreferences = SecureChatPreferences (
    crypto: "[CRYPTO]", // (e.g. VSSCrypto())
    identityPrivateKey: aliceKey.privateKey,
    identityCard: aliceCard.card!,
    accessToken: "[YOUR_ACCESS_TOKEN_HERE]")

self.secureChat = SecureChat(preferences: secureChatPreferences)

try self.secureChat.initialize()

self.secureChat.rotateKeys(desiredNumberOfCards: 100) { error in
    //...
}
```
After chat initialization, Alice and Bob can start their PFS communication.

## <a name="head5"></a> Send & Receive Message

Once Recipients initialized a PFS Chat, they can communicate.
Alice establishes a secure PFS conversation with Bob, encrypts and sends the message to him:

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
Then Bob decrypts the incoming message using the conversation he has just created:

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

With the open session, which works in both directions, Alice and Bob can continue PFS encrypted communication.
