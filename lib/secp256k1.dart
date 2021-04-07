library secp256k1;

import './src/base.dart' as base;

class PrivateKey {
  late BigInt D;

  /// get the unique public key of the private key on secp256k1 curve
  PublicKey get publicKey {
    final point = base.getPointByBig(
        D, base.secp256k1.p, base.secp256k1.a, base.secp256k1.G);

    return PublicKey(point[0], point[1]);
  }

  /// generate a private key from random number
  PrivateKey(this.D);

  /// generate a private key from random number
  PrivateKey.generate() {
    D = base.getPrivKeyByRand(base.secp256k1.n);
  }

  /// convert a hex string to a private key(bigint)
  PrivateKey.fromHex(String hexString) {
    D = BigInt.parse(hexString, radix: 16);
  }

  /// generate a hex string from a private key(bigint)
  String toHex() {
    return D.toRadixString(16).padLeft(64, '0');
  }

  /// sign the **hash** of message with the private key
  Signature signature(String hexHash) {
    final rs = base.sign(base.secp256k1.n, base.secp256k1.p, base.secp256k1.a,
        D, base.secp256k1.G, BigInt.parse(hexHash, radix: 16));

    return Signature(rs[0], rs[1]);
  }

  @override
  bool operator ==(other) {
    return other is PrivateKey && (D == other.D);
  }
}

class PublicKey {
  late BigInt X;
  late BigInt Y;

  PublicKey(this.X, this.Y);

  /// convert a hex string to a public key
  PublicKey.fromHex(String hexString) {
    final point = base.hex2Point(hexString);
    X = point[0];
    Y = point[1];
  }

  /// convert a compressed hex string to a public key(List of 2 bigints)
  PublicKey.fromCompressedHex(String hexString) {
    final point = base.hex2PointFromCompress(hexString);
    X = point[0];
    Y = point[1];
  }

  /// generate a hex string from a public key
  String toHex() {
    return base.point2Hex([X, Y]);
  }

  /// generate a compressed hex string from a public key
  String toCompressedHex() {
    return base.point2HexInCompress([X, Y]);
  }

  @override
  String toString() {
    return toHex();
  }

  @override
  bool operator ==(other) {
    return other is PublicKey && (X == other.X && Y == other.Y);
  }
}

class Signature {
  late BigInt R;
  late BigInt S;

  Signature(this.R, this.S);
  Signature.fromHexes(String r, s) {
    R = BigInt.parse(r, radix: 16);
    S = BigInt.parse(s, radix: 16);
  }

  /// verify the sign and the **hash** of message with the public key
  bool verify(PublicKey publicKey, String hexHash) {
    return base.verify(
      base.secp256k1.n,
      base.secp256k1.p,
      base.secp256k1.a,
      base.secp256k1.G,
      [publicKey.X, publicKey.Y],
      [R, S],
      BigInt.parse(hexHash, radix: 16),
    );
  }

  List<BigInt> toBigInts() {
    return [R, S];
  }

  List<String> toHexes() {
    return [
      R.toRadixString(16).padLeft(64, '0'),
      S.toRadixString(16).padLeft(64, '0')
    ];
  }

  String toRawHex() {
    return R.toRadixString(16).padLeft(64, '0') +
        S.toRadixString(16).padLeft(64, '0');
  }

  @override
  String toString() {
    return toRawHex();
  }

  @override
  bool operator ==(other) {
    return other is Signature && (R == other.R && S == other.S);
  }
}
