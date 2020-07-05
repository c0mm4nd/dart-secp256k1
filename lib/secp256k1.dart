library secp256k1;

import 'package:secp256k1/src/base.dart' as base;

/// generate a private key from random number
BigInt generatePrivateKey() {
  return base.getPrivteKeyByRand(base.secp256k1.n);
}

/// generate a hex string from a private key(bigint)
String privateKeyToHex(BigInt privateKey) {
  return privateKey.toRadixString(16);
}

/// convert a hex string to a private key(bigint)
BigInt hexToPrivateKey(String hexPrivateKey) {
  return BigInt.parse(hexPrivateKey, radix: 16);
}

/// generate a compressed hex string from a public key(List of 2 bigints)
String publicKeyToHex(List<BigInt> publicKey) {
  return base.point2Hex(publicKey);
}

/// generate a compressed hex string from a public key(List of 2 bigints)
String publicKeyToCompressHex(List<BigInt> publicKey) {
  return base.point2HexInCompress(publicKey);
}

/// convert a hex string to a public key(List of 2 bigints)
List<BigInt> hexToPublicKey(String hexPublicKey) {
  return base.hex2Point(hexPublicKey);
}

/// convert a compressed hex string to a public key(List of 2 bigints)
List<BigInt> compressHexToPublicKey(String hexPublicKey) {
  return base.hex2PointFromCompress(hexPublicKey);
}

/// get the unique public key of the private key on secp256k1 curve
List<BigInt> getPublic(BigInt privateKey) {
  return base.getPointByBig(
      privateKey, base.secp256k1.p, base.secp256k1.a, base.secp256k1.G);
}

/// sign the **hash** of message with the private key
/// return R&S(a list of 2 BigInt)
List<BigInt> sign(BigInt privateKey, String hexHash) {
  return base.sign(base.secp256k1.n, base.secp256k1.p, base.secp256k1.a,
      privateKey, base.secp256k1.G, BigInt.parse(hexHash, radix: 16));
}

/// verify the sign(R&S) and the **hash** of message with the public key
bool verify(List<BigInt> publicKey, List<BigInt> sign, String hexHash) {
  return base.verify(
    base.secp256k1.n,
    base.secp256k1.p,
    base.secp256k1.a,
    base.secp256k1.G,
    publicKey,
    sign,
    BigInt.parse(hexHash, radix: 16),
  );
}
