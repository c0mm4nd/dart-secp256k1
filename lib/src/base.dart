// Point => List<BigInt>
// PrivateKey => BigInt
// PublicKey => List<BigInt>
import 'dart:math';

import 'package:crypto/crypto.dart';

const secp256k1Params = {
  'p': 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
  'a': '0',
  'b': '7',
  'Gx': '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  'Gy': '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
  'n': 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
  'h': '1',
};

class Curve {
  late BigInt p, a, b, n, h;
  late List<BigInt> G;
  Curve(Map params) {
    p = BigInt.parse(params['p'], radix: 16);
    a = BigInt.parse(params['a'], radix: 16);
    b = BigInt.parse(params['b'], radix: 16);
    n = BigInt.parse(params['n'], radix: 16);
    h = BigInt.parse(params['h'], radix: 16);
    G = [
      BigInt.parse(secp256k1Params['Gx']!, radix: 16),
      BigInt.parse(secp256k1Params['Gy']!, radix: 16)
    ];
  }
}

var secp256k1 = Curve(secp256k1Params);

BigInt hex2Big(String string, {radix = 16}) {
  return BigInt.parse(string, radix: radix);
}

List<BigInt> big2Point(BigInt n) {
  return hex2Point(n.toRadixString(16));
}

List<BigInt> hex2Point(String hex) {
  final len = 130;
  if (hex.length != len) {
    throw ('point length must be $len!');
  }

  if (hex.substring(0, 2) != '04') {
    throw ('point prefix incorrect!');
  }

  var point = [
    BigInt.parse(hex.substring(2, 66), radix: 16),
    BigInt.parse(hex.substring(66, 130), radix: 16),
  ];

  // Validate that the decoded point actually lies on secp256k1.
  if (!isOnCurve(point, secp256k1.p, secp256k1.a)) {
    throw ('public key is not on the curve');
  }

  return point;
}

List<BigInt> hex2PointFromCompress(String hex) {
  final len = 66;
  if (hex.length != len) {
    throw ('point length must be $len!');
  }

  var firstByte = int.parse(hex.substring(0, 2), radix: 16);

  if ((firstByte & ~1) != 2) {
    throw ('point prefix incorrect!');
  }

  // The curve equation for secp256k1 is: y^2 = x^3 + 7.
  var x = BigInt.parse(hex.substring(2, 66), radix: 16);

  var ySqared =
      ((x.modPow(BigInt.from(3), secp256k1.p)) + BigInt.from(7)) % secp256k1.p;

  // power = (p+1) // 4
  var p1 = secp256k1.p + BigInt.from(1); // p+1
  var power = (p1 - p1 % BigInt.from(4)) ~/ BigInt.from(4);
  var y = ySqared.modPow(power, secp256k1.p);

  var sq = y.pow(2) % secp256k1.p;
  if (sq != ySqared) {
    throw ('failed to retrieve y of public key from hex');
  }

  var firstBit = (y & BigInt.one).toInt();
  if (firstBit != (firstByte & 1)) {
    y = secp256k1.p - y;
  }

  return [
    x,
    y,
  ];
}

String point2Hex(List<BigInt> point) {
  return '04${point[0].toRadixString(16).padLeft(64, '0')}${point[1].toRadixString(16).padLeft(64, '0')}'; // 2+64+64 = 130
}

String point2HexInCompress(List<BigInt> point) {
  // var byteLen = 32; //(256 + 7) >> 3 //  => so len of str is (32+1) * 2 = 66;
  var firstBit = 2 + (point[1] & BigInt.one).toInt();
  var prefix = firstBit.toRadixString(16).padLeft(2, '0');

  return prefix + point[0].toRadixString(16).padLeft(64, '0');
}

BigInt point2Big(List<BigInt> point) {
  return BigInt.parse(point2Hex(point), radix: 16);
}

BigInt positiveMod(BigInt n, BigInt modN) {
  return (n % modN + modN) % modN;
}

BigInt inverseMulti(BigInt x, BigInt modNum) {
  // Modular multiplicative inverse of x mod modNum.
  var v = (x % modNum + modNum) % modNum;
  if (v == BigInt.zero) {
    throw ('multiplicative inverse modulo is no answer!');
  }
  return v.modInverse(modNum);
}

// getPrivKeyByRand returns a cryptographically secure, uniformly distributed
// scalar in [1, n-1] using rejection sampling over Random.secure().
BigInt getPrivKeyByRand(BigInt n) {
  if (n <= BigInt.one) {
    throw ('curve order must be greater than 1');
  }
  var random = Random.secure();
  var byteLen = (n.bitLength + 7) >> 3;
  var excess = byteLen * 8 - n.bitLength;

  while (true) {
    var bytes = List<int>.generate(byteLen, (_) => random.nextInt(256));
    var d = _octetsToBig(bytes);
    if (excess > 0) {
      d = d >> excess; // drop bits beyond the order's bit length
    }
    if (d >= BigInt.one && d < n) {
      return d;
    }
  }
}

// _octetsToBig interprets a big-endian byte list as a non-negative BigInt.
BigInt _octetsToBig(List<int> bytes) {
  var ret = BigInt.zero;
  for (var b in bytes) {
    ret = (ret << 8) | BigInt.from(b & 0xff);
  }
  return ret;
}

// _bigToOctets serializes v as a big-endian byte list of exactly [roLen] bytes.
List<int> _bigToOctets(BigInt v, int roLen) {
  var hex = v.toRadixString(16);
  if (hex.length.isOdd) {
    hex = '0' + hex;
  }
  var bytes = List<int>.generate(
      hex.length ~/ 2, (i) => int.parse(hex.substring(2 * i, 2 * i + 2), radix: 16));
  if (bytes.length < roLen) {
    bytes = List<int>.filled(roLen - bytes.length, 0) + bytes;
  } else if (bytes.length > roLen) {
    bytes = bytes.sublist(bytes.length - roLen);
  }
  return bytes;
}

// generateSecret deterministically derives the ECDSA nonce k per RFC 6979 §3.2
// using HMAC-SHA256. Determinism removes any dependence on the quality of the
// RNG at signing time and prevents catastrophic nonce reuse/bias.
BigInt generateSecret(BigInt q, BigInt x, List<int> hash) {
  var holen = 32; // SHA-256 output length in bytes
  var qlen = q.bitLength;
  var rolen = (qlen + 7) >> 3;

  // bits2octets(hash)
  var truncated = hash.length > rolen ? hash.sublist(0, rolen) : hash;
  var z1 = _octetsToBig(truncated);
  var z2 = z1 - q;
  var bx = _bigToOctets(x, rolen) + _bigToOctets(z2.sign < 0 ? z1 : z2, rolen);

  var v = List<int>.filled(holen, 0x01);
  var k = List<int>.filled(holen, 0x00);

  k = Hmac(sha256, k).convert(v + [0x00] + bx).bytes;
  v = Hmac(sha256, k).convert(v).bytes;
  k = Hmac(sha256, k).convert(v + [0x01] + bx).bytes;
  v = Hmac(sha256, k).convert(v).bytes;

  while (true) {
    var t = <int>[];
    while (t.length * 8 < qlen) {
      v = Hmac(sha256, k).convert(v).bytes;
      t = t + v;
    }
    var secret = _octetsToBig(t.length > rolen ? t.sublist(0, rolen) : t);
    if (secret >= BigInt.one && secret < q) {
      return secret;
    }
    k = Hmac(sha256, k).convert(v + [0x00]).bytes;
    v = Hmac(sha256, k).convert(v).bytes;
  }
}

List<BigInt> addSamePoint(BigInt x1, BigInt y1, BigInt modNum, BigInt a) {
  var ru = positiveMod(
      (BigInt.from(3) * x1.pow(2) + a) * inverseMulti(BigInt.two * y1, modNum),
      modNum);
  var x3 = positiveMod(ru.pow(2) - (BigInt.two * x1), modNum);
  var y3 = positiveMod(ru * (x1 - x3) - y1, modNum);
  return [x3, y3];
}

List<BigInt> addDiffPoint(
    BigInt x1, BigInt y1, BigInt x2, BigInt y2, BigInt modNum) {
  var ru = positiveMod((y2 - y1) * inverseMulti(x2 - x1, modNum), modNum);
  var x3 = positiveMod(ru.pow(2) - x1 - x2, modNum);
  var y3 = positiveMod(ru * (x1 - x3) - y1, modNum);
  return [x3, y3];
}

// _pointAdd adds two affine points, using null for the point at infinity and
// correctly handling the doubling (P == Q) and inverse (P == -Q) cases that the
// bare addDiffPoint/addSamePoint helpers do not.
List<BigInt>? _pointAdd(
    List<BigInt>? pA, List<BigInt>? pB, BigInt p, BigInt a) {
  if (pA == null) return pB;
  if (pB == null) return pA;
  if (pA[0] == pB[0]) {
    if ((pA[1] + pB[1]) % p == BigInt.zero) return null; // P + (-P) = ∞
    return addSamePoint(pA[0], pA[1], p, a); // P == Q -> double
  }
  return addDiffPoint(pA[0], pA[1], pB[0], pB[1], p);
}

List<BigInt>? _pointDouble(List<BigInt>? pA, BigInt p, BigInt a) {
  if (pA == null) return null;
  if (pA[1] % p == BigInt.zero) return null;
  return addSamePoint(pA[0], pA[1], p, a);
}

// getPointByBig returns n*G using a Montgomery ladder: every scalar bit runs
// exactly one point addition and one point doubling, so the sequence of point
// operations does not depend on the (secret) scalar.
List<BigInt> getPointByBig(BigInt n, BigInt p, BigInt a, List<BigInt> pointG) {
  List<BigInt>? r0; // ∞
  List<BigInt>? r1 = [pointG[0], pointG[1]];

  var bin = n.toRadixString(2);
  for (var i = 0; i < bin.length; i++) {
    if (bin[i] == '1') {
      r0 = _pointAdd(r0, r1, p, a);
      r1 = _pointDouble(r1, p, a);
    } else {
      r1 = _pointAdd(r0, r1, p, a);
      r0 = _pointDouble(r0, p, a);
    }
  }

  if (r0 == null) {
    throw ('scalar multiplication produced the point at infinity');
  }
  return r0;
}

// sign produces a deterministic ECDSA signature per RFC 6979, with low-S
// normalization (BIP-62) to avoid signature malleability.
List<BigInt> sign(BigInt n, BigInt p, BigInt a, BigInt d, List<BigInt> pointG,
    BigInt bigHash) {
  if (d < BigInt.one || d >= n) {
    throw ('invalid private key: must be in [1, n-1]');
  }

  var rolen = (n.bitLength + 7) >> 3;
  var hashOctets = _bigToOctets(bigHash, rolen);

  var k = generateSecret(n, d, hashOctets);

  var R = getPointByBig(k, p, a, pointG);
  var r = positiveMod(R[0], n);
  if (r == BigInt.zero) {
    throw ('calculated R is zero');
  }

  var kInv = inverseMulti(k, n);
  var s = positiveMod((bigHash + r * d) * kInv, n);
  if (s == BigInt.zero) {
    throw ('calculated S is zero');
  }

  // low-S normalization (BIP-62): keep s in the lower half of [1, n-1].
  if (s > (n >> 1)) {
    s = n - s;
  }

  return [r, s];
}

// isOnCurve reports whether the affine point (x, y) satisfies the curve
// equation y^2 = x^3 + a*x + b (mod p) and has coordinates in [0, p). [b]
// defaults to the secp256k1 constant.
bool isOnCurve(List<BigInt> point, BigInt p, BigInt a, [BigInt? b]) {
  b ??= secp256k1.b;
  var x = point[0];
  var y = point[1];
  if (x < BigInt.zero || x >= p || y < BigInt.zero || y >= p) {
    return false;
  }
  var lhs = (y * y) % p;
  var rhs = (x * x % p * x + a * x + b) % p;
  return lhs == rhs;
}

bool verify(BigInt n, BigInt p, BigInt a, List<BigInt> pointG,
    List<BigInt> pointQ, List<BigInt> sign, BigInt bigHash) {
  var r = sign[0];
  var s = sign[1];

  if (r < BigInt.one || r >= n) return false;
  if (s < BigInt.one || s >= n) return false;

  // Reject public keys that are not valid curve points (guards against
  // invalid-curve inputs reaching the group arithmetic).
  if (!isOnCurve(pointQ, p, a)) return false;

  // if (!(r > BigInt.one && r < n && s > BigInt.one && s < n)) {
  //   return false;
  // }

  var e = bigHash;
  var w = inverseMulti(s, n);
  var u1 = positiveMod((e * w), n);
  var u2 = positiveMod((r * w), n);

  // A zero scalar yields the point at infinity; combine through the
  // infinity-aware _pointAdd so that edge cases (u1 == 0, or u1*G == -(u2*Q))
  // return false instead of throwing from the raw affine helpers.
  var u1Point = u1 == BigInt.zero ? null : getPointByBig(u1, p, a, pointG);
  var u2Point = u2 == BigInt.zero ? null : getPointByBig(u2, p, a, pointQ);

  var pointR = _pointAdd(u1Point, u2Point, p, a);
  if (pointR == null) {
    return false; // sum is the point at infinity
  }
  var v = positiveMod(pointR[0], n);
  return v == r;
}
