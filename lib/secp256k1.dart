library secp256k1;

import 'package:secp256k1/base.dart' as base;

BigInt generatePrivateKey() {
  return base.getPrivteKeyByRand(base.secp256k1.n);
}

String privateKeyToHex(BigInt privateKey) {
  return privateKey.toRadixString(16);
}

BigInt hexToPrivateKey(String hexPrivateKey) {
  return BigInt.parse(hexPrivateKey, radix: 16);
}

String publicKeyToHex(List<BigInt> publicKey) {
  return base.point2Hex(publicKey);
}

String publicKeyToCompressHex(List<BigInt> publicKey) {
  return base.point2HexInCompress(publicKey);
}

List<BigInt> hexToPublicKey(String hexPublicKey) {
  return base.hex2Point(hexPublicKey);
}

List<BigInt> compressHexToPublicKey(String hexPublicKey) {
  return base.hex2PointFromCompress(hexPublicKey);
}

List<BigInt> getPublic(BigInt privateKey) {
  return base.getPointByBig(
      privateKey, base.secp256k1.p, base.secp256k1.a, base.secp256k1.G);
}

List<BigInt> sign(BigInt privateKey, String hexHash) {
  return base.sign(base.secp256k1.n, base.secp256k1.p, base.secp256k1.a,
      privateKey, base.secp256k1.G, BigInt.parse(hexHash, radix: 16));
}

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
