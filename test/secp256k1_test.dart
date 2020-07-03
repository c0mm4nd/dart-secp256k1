import 'package:secp256k1/secp256k1.dart';
import 'package:test/test.dart';

void main() {
  group('A group of tests', () {
    test('Test', () {
      var pk1 = hexToPrivateKey(
          'c37c299bb7f5ffd8d9329d052983342a8c3234ff3b3fa32a292187341f7146d7');
      var pub1 = getPublic(pk1);
      var hexPub = publicKeyToCompressHex(pub1);
      expect(hexPub,
          '03a12b6218425127f186011ff4c203b8d6ea651877c46f12484b2eda492596484f');
      expect(
          compressHexToPublicKey(
              '03a12b6218425127f186011ff4c203b8d6ea651877c46f12484b2eda492596484f'),
          pub1);

      var pk2 = hexToPrivateKey(
          '52d62cfcf7062af53f7bec124fe9285eaa8a8963411ba613b7432be73565b6b3');
      var pub2 = getPublic(pk2);
      hexPub = publicKeyToHex(pub2);
      expect(hexPub,
          '0449aedf74e8f87811761cf3d5fa8f8eaa42b4c657efc986939229a898b3ee27a000f9a247290fb5716c2db17dc193fd4e3f7b36a9947b477c6f0769c15fb8bf79');
      expect(
          hexToPublicKey(
              '0449aedf74e8f87811761cf3d5fa8f8eaa42b4c657efc986939229a898b3ee27a000f9a247290fb5716c2db17dc193fd4e3f7b36a9947b477c6f0769c15fb8bf79'),
          pub2);

      var msg =
          'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'; // sha256 of 'hello world';
      var R_S = sign(pk2, msg);
      expect(verify(pub2, R_S, msg), true);
      expect(
          verify(pub1, R_S,
              'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde8'),
          false);
      expect(
          verify(pub2, R_S,
              'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde8'),
          false);
      expect(
          verify(pub1, [BigInt.zero, BigInt.zero],
              'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde8'),
          false);
    });
  });
}
