// Point => List<BigInt>
// PrivateKey => BigInt
// PublicKey => List<BigInt>
import 'dart:math';

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
  BigInt p, a, b, n, h;
  List<BigInt> G;
  Curve(Map params) {
    p = BigInt.parse(params['p'], radix: 16);
    a = BigInt.parse(params['a'], radix: 16);
    b = BigInt.parse(params['b'], radix: 16);
    n = BigInt.parse(params['n'], radix: 16);
    h = BigInt.parse(params['h'], radix: 16);
    G = [
      BigInt.parse(secp256k1Params['Gx'], radix: 16),
      BigInt.parse(secp256k1Params['Gy'], radix: 16)
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
    throw ('point length must be ${len}!');
  }

  if (hex.substring(0, 2) != '04') {
    throw ('point prefix incorrect!');
  }

  return [
    BigInt.parse(hex.substring(2, 66), radix: 16),
    BigInt.parse(hex.substring(66, 130), radix: 16),
  ];
}

List<BigInt> hex2PointFromCompress(String hex) {
  final len = 66;
  if (hex.length != len) {
    throw ('point length must be ${len}!');
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

BigInt postiveMod(BigInt n, BigInt modN) {
  return (n % modN + modN) % modN;
}

BigInt inverseMulti(BigInt x, BigInt modNum) {
  var x1 = BigInt.one;
  var x2 = BigInt.zero;
  var x3 = modNum;

  var y1 = BigInt.zero;
  var y2 = BigInt.one;
  var y3 = (x % modNum + modNum) % modNum;

  BigInt q;
  BigInt t1, t2, t3;
  while (true) {
    if (y3 == BigInt.zero) {
      throw ('multiplicative inverse modulo is no answer!');
    }
    if (y3 == BigInt.one) return y2;

    q = BigInt.from(x3 / y3);

    t1 = x1 - q * y1;
    t2 = x2 - q * y2;
    t3 = x3 - q * y3;

    x1 = y1;
    x2 = y2;
    x3 = y3;

    y1 = t1;
    y2 = t2;
    y3 = t3;
  }
}

BigInt getPrivKeyByRand(BigInt n) {
  var nHex = n.toRadixString(16);
  var privteKeyList = <String>[];
  var random = Random.secure();

  for (var i = 0; i < nHex.length; i++) {
    var rand16Num =
        (random.nextInt(100) / 100 * int.parse(nHex[i], radix: 16)).round();
    privteKeyList.add(rand16Num.toRadixString(16));
  }

  var D = BigInt.parse(privteKeyList.join(''), radix: 16);
  if (D == BigInt.zero) {
    return getPrivKeyByRand(n);
  }

  return D;
}

List<BigInt> addSamePoint(BigInt x1, BigInt y1, BigInt modNum, BigInt a) {
  var ru = postiveMod(
      (BigInt.from(3) * x1.pow(2) + a) * inverseMulti(BigInt.two * y1, modNum),
      modNum);
  var x3 = postiveMod(ru.pow(2) - (BigInt.two * x1), modNum);
  var y3 = postiveMod(ru * (x1 - x3) - y1, modNum);
  return [x3, y3];
}

List<BigInt> addDiffPoint(
    BigInt x1, BigInt y1, BigInt x2, BigInt y2, BigInt modNum) {
  var ru = postiveMod((y2 - y1) * inverseMulti(x2 - x1, modNum), modNum);
  var x3 = postiveMod(ru.pow(2) - x1 - x2, modNum);
  var y3 = postiveMod(ru * (x1 - x3) - y1, modNum);
  return [x3, y3];
}

List<BigInt> getPointByBig(BigInt n, BigInt p, BigInt a, List<BigInt> pointG) {
  var bin = n.toRadixString(2);
  List<BigInt> nowPoint;
  var nextPoint = pointG;
  for (var i = bin.length - 1; i >= 0; i--) {
    if (bin[i] == '1') {
      if (nowPoint == null) {
        nowPoint = nextPoint;
      } else {
        nowPoint = addDiffPoint(
            nowPoint[0], nowPoint[1], nextPoint[0], nextPoint[1], p);
      }
    }

    nextPoint = addSamePoint(nextPoint[0], nextPoint[1], p, a);
  }

  return nowPoint;
}

// signRFC6979
List<BigInt> sign(BigInt n, BigInt p, BigInt a, BigInt d, List<BigInt> pointG,
    BigInt bigHash) {
  BigInt k;
  List<BigInt> R;
  var r = BigInt.zero;

  while (r == BigInt.zero) {
    k = getPrivKeyByRand(n);

    R = getPointByBig(k, p, a, pointG);
    r = postiveMod(R[0], n);
  }

  var e = bigHash;
  var s = postiveMod(((e + (r * d)) * inverseMulti(k, n)), n);

  if (s == BigInt.zero) {
    return sign(n, p, a, d, pointG, bigHash);
  }
  return [r, s];
}

bool verify(BigInt n, BigInt p, BigInt a, List<BigInt> pointG,
    List<BigInt> pointQ, List<BigInt> sign, BigInt bigHash) {
  var r = sign[0];
  var s = sign[1];

  if (!(r > BigInt.zero && r < n && s > BigInt.zero && s < n)) {
    return false;
  }

  var e = bigHash;
  var w = inverseMulti(s, n);
  var u1 = postiveMod((e * w), n);
  var u2 = postiveMod((r * w), n);
  var u1Point = getPointByBig(u1, p, a, pointG);
  var u2Point = getPointByBig(u2, p, a, pointQ);

  List<BigInt> pointR;
  if (u1Point[0] == u2Point[0] && u1Point[1] == u2Point[1]) {
    pointR = addSamePoint(u1Point[0], u1Point[1], p, a);
  } else {
    pointR = addDiffPoint(u1Point[0], u1Point[1], u2Point[0], u2Point[1], p);
  }
  if (pointR[0] == BigInt.zero && pointR[1] == BigInt.zero) {
    return false;
  }
  var v = postiveMod(pointR[0], n);
  if (v == r) {
    return true;
  }
  return false;
}
