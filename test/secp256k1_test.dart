import 'package:secp256k1/secp256k1.dart';
import 'package:test/test.dart';

void main() {
  group('A group of tests', () {
    var hello_world =
        'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
    var goodbye_world =
        '9150e02727e29ca8522c29ad4aa5a8343c21ccf909b40f73c41bf478df7e6fc3';
    var vec = [
      [
        'c37c299bb7f5ffd8d9329d052983342a8c3234ff3b3fa32a292187341f7146d7',
        '03a12b6218425127f186011ff4c203b8d6ea651877c46f12484b2eda492596484f'
      ],
      [
        '52d62cfcf7062af53f7bec124fe9285eaa8a8963411ba613b7432be73565b6b3',
        '0449aedf74e8f87811761cf3d5fa8f8eaa42b4c657efc986939229a898b3ee27a000f9a247290fb5716c2db17dc193fd4e3f7b36a9947b477c6f0769c15fb8bf79'
      ],
      [
        '8db69356f772b318c523bbcaa5bddfeddae118ee6aca574e7d2e4332e35fc238',
        '0247d3faa09ce8c4bd46c9b89a680d5b1064bf2bcd321a47358c02e9527c2387e6'
      ]
    ];

    test('Test', () {
      var pk1 = hexToPrivateKey(vec[0][0]);
      var pub1 = getPublic(pk1);
      var hexPub = publicKeyToCompressHex(pub1);
      expect(hexPub, vec[0][1]);
      expect(compressHexToPublicKey(vec[0][1]), pub1);

      var pk2 = hexToPrivateKey(vec[1][0]);
      var pub2 = getPublic(pk2);
      hexPub = publicKeyToHex(pub2);
      expect(hexPub, vec[1][1]);
      expect(hexToPublicKey(vec[1][1]), pub2);

      var msg = hello_world; // sha256 of 'hello world';
      var R_S = sign(pk2, msg);
      expect(verify(pub2, R_S, msg), true);
      expect(verify(pub1, R_S, msg), false);
      expect(verify(pub2, R_S, goodbye_world), false);
      expect(verify(pub1, [BigInt.zero, BigInt.zero], hello_world), false);
    });
    test('compress prefix', () {
      // add
      var pk3 = hexToPrivateKey(vec[2][0]);
      var pub3 = getPublic(pk3);
      var hexPub = publicKeyToCompressHex(pub3);
      expect(hexPub, vec[2][1]);
      expect(compressHexToPublicKey(vec[2][1]), pub3);
    });
  });
}
