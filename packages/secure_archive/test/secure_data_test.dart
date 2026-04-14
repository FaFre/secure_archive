import 'dart:convert';
import 'dart:typed_data';

import 'package:secure_archive/secure_archive.dart';
import 'package:secure_archive/src/data/secure_data.dart' as data;
import 'package:test/test.dart';

void main() {
  final argon2 = Argon2Params.memoryConstrained();

  group('SecureData', () {
    test('encrypt and decrypt round-trip', () async {
      final secureData = SecureData(argon2Params: argon2);
      final plaintext = utf8.encode('hello world');

      final blob = await secureData.encrypt(plaintext, 'password');
      final decrypted = await secureData.decrypt(blob, 'password');

      expect(decrypted, equals(plaintext));
    });

    test('encrypt and decrypt JSON settings', () async {
      final secureData = SecureData(argon2Params: argon2);
      final settings = {
        'theme': 'dark',
        'fontSize': 14,
        'notifications': true,
      };
      final plaintext = utf8.encode(jsonEncode(settings));

      final blob = await secureData.encrypt(plaintext, 'password');
      final decrypted = await secureData.decrypt(blob, 'password');

      final restored = jsonDecode(utf8.decode(decrypted));
      expect(restored, equals(settings));
    });

    test('round-trip with compression', () async {
      final secureData = SecureData(argon2Params: argon2);
      final plaintext = utf8.encode('repeated ' * 100);

      final blob = await secureData.encrypt(
        plaintext,
        'password',
        compress: true,
      );
      final decrypted = await secureData.decrypt(blob, 'password');

      expect(decrypted, equals(plaintext));
    });

    test('compressed blob is smaller than uncompressed for repetitive data',
        () async {
      final secureData = SecureData(argon2Params: argon2);
      final plaintext = utf8.encode('repeated ' * 100);

      final uncompressed = await secureData.encrypt(plaintext, 'password');
      final compressed = await secureData.encrypt(
        plaintext,
        'password',
        compress: true,
      );

      expect(compressed.length, lessThan(uncompressed.length));
    });

    test('wrong password throws', () async {
      final secureData = SecureData(argon2Params: argon2);
      final plaintext = utf8.encode('secret');

      final blob = await secureData.encrypt(plaintext, 'correct');

      await expectLater(
        secureData.decrypt(blob, 'wrong'),
        throwsA(isA<Exception>()),
      );
    });

    test('empty plaintext round-trips', () async {
      final secureData = SecureData(argon2Params: argon2);

      final blob = await secureData.encrypt([], 'password');
      final decrypted = await secureData.decrypt(blob, 'password');

      expect(decrypted, isEmpty);
    });

    test('empty password throws on encrypt', () async {
      final secureData = SecureData(argon2Params: argon2);

      await expectLater(
        secureData.encrypt([1, 2, 3], ''),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('empty password throws on decrypt', () async {
      final secureData = SecureData(argon2Params: argon2);
      final blob = await secureData.encrypt([1, 2, 3], 'password');

      await expectLater(
        secureData.decrypt(blob, ''),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('wire format', () {
    test('blob has correct structure', () async {
      final plaintext = utf8.encode('test');

      final blob = await data.encryptData(
        data: plaintext,
        password: 'password',
        argon2Params: argon2,
        compress: false,
      );

      // version(1) + flags(1) + salt(16) + nonce(12) + ciphertext(N) + mac(16)
      expect(blob.length, greaterThanOrEqualTo(46));
      expect(blob[0], equals(1)); // version
      expect(blob[1], equals(0)); // no compression flag
    });

    test('compression flag is set when compressed', () async {
      final blob = await data.encryptData(
        data: utf8.encode('test'),
        password: 'password',
        argon2Params: argon2,
        compress: true,
      );

      expect(blob[0], equals(1)); // version
      expect(blob[1] & 1, equals(1)); // gzip flag set
    });

    test('truncated blob throws FormatException', () async {
      await expectLater(
        data.decryptData(
          data: Uint8List(10),
          password: 'password',
          argon2Params: argon2,
        ),
        throwsA(isA<FormatException>()),
      );
    });

    test('unsupported version throws FormatException', () async {
      final blob = Uint8List(46);
      blob[0] = 99; // bad version

      await expectLater(
        data.decryptData(
          data: blob,
          password: 'password',
          argon2Params: argon2,
        ),
        throwsA(isA<FormatException>()),
      );
    });

    test('tampered ciphertext throws', () async {
      final blob = await data.encryptData(
        data: utf8.encode('secret'),
        password: 'password',
        argon2Params: argon2,
        compress: false,
      );

      // Flip a byte in the ciphertext region
      final tampered = Uint8List.fromList(blob);
      tampered[30] ^= 0xFF;

      await expectLater(
        data.decryptData(
          data: tampered,
          password: 'password',
          argon2Params: argon2,
        ),
        throwsA(isA<Exception>()),
      );
    });

    test('tampered MAC throws', () async {
      final blob = await data.encryptData(
        data: utf8.encode('secret'),
        password: 'password',
        argon2Params: argon2,
        compress: false,
      );

      final tampered = Uint8List.fromList(blob);
      tampered[tampered.length - 1] ^= 0xFF;

      await expectLater(
        data.decryptData(
          data: tampered,
          password: 'password',
          argon2Params: argon2,
        ),
        throwsA(isA<Exception>()),
      );
    });

    test('tampered flags byte throws', () async {
      final blob = await data.encryptData(
        data: utf8.encode('secret'),
        password: 'password',
        argon2Params: argon2,
        compress: true,
      );

      // Flip the gzip flag off — should fail authentication
      final tampered = Uint8List.fromList(blob);
      tampered[1] ^= 0x01;

      await expectLater(
        data.decryptData(
          data: tampered,
          password: 'password',
          argon2Params: argon2,
        ),
        throwsA(isA<Exception>()),
      );
    });

    test('tampered version byte throws', () async {
      final blob = await data.encryptData(
        data: utf8.encode('secret'),
        password: 'password',
        argon2Params: argon2,
        compress: false,
      );

      // Change version from 1 to 2 — caught by format check before AAD,
      // but verify it doesn't silently succeed.
      final tampered = Uint8List.fromList(blob);
      tampered[0] = 2;

      await expectLater(
        data.decryptData(
          data: tampered,
          password: 'password',
          argon2Params: argon2,
        ),
        throwsA(anything),
      );
    });

    test('each encrypt produces unique salt and nonce', () async {
      final plaintext = utf8.encode('same data');
      const password = 'password';

      final blob1 = await data.encryptData(
        data: plaintext,
        password: password,
        argon2Params: argon2,
        compress: false,
      );
      final blob2 = await data.encryptData(
        data: plaintext,
        password: password,
        argon2Params: argon2,
        compress: false,
      );

      // Salt (bytes 2-18) should differ
      final salt1 = blob1.sublist(2, 18);
      final salt2 = blob2.sublist(2, 18);
      expect(salt1, isNot(equals(salt2)));

      // Nonce (bytes 18-30) should differ
      final nonce1 = blob1.sublist(18, 30);
      final nonce2 = blob2.sublist(18, 30);
      expect(nonce1, isNot(equals(nonce2)));
    });
  });
}
