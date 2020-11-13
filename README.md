# dart-secp256k1

Pure secp256k1 implement for dart language.

secp256k1 refers to the parameters of the elliptic curve used in Bitcoin's public-key cryptography, and is defined in Standards for Efficient Cryptography (SEC) (Certicom Research, http://www.secg.org/sec2-v2.pdf). Currently Bitcoin uses secp256k1 with the ECDSA algorithm, though the same curve with the same public/private keys can be used in some other algorithms such as Schnorr.

## Usage

library secp256k1 uses pure dart and its basic types to represent all matters:

```
PrivateKey => BigInt
PublickKey => List<BigInt>(2)
```

A simple usage example:

```dart
var pk = PrivateKey.fromHex('c37c299bb7f5ffd8d9329d052983342a8c3234ff3b3fa32a292187341f7146d7');
var pub = pk1.publicKey;
print(pub.toHex());
print(pub.toCompressedHex());

var messageHash = 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
var sig = pk.signature(messageHash);
print(sig.verify(pub, messageHash)); // ok
```

## Features and bugs

Please file feature requests and bugs at the [issue tracker][tracker].

[tracker]: https://github.com/c0mm4nd/dart-secp256k1/issues
