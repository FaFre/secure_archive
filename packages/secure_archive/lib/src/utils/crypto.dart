import 'dart:async';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/helpers.dart';
import 'package:secure_archive/src/data/argon2_params.dart';

Uint8List generateRandomBytes(int length) {
  final bytes = Uint8List(length);

  fillBytesWithSecureRandom(bytes);

  return bytes;
}

Future<SecretKey> deriveArgon2idKey(
  Argon2Params params,
  String password,
  Uint8List salt,
) {
  final cipher = Chacha20.poly1305Aead();

  final algorithm = Argon2id(
    parallelism: params.parallelism,
    memory: params.memory,
    iterations: params.iterations,
    hashLength: cipher.secretKeyLength,
  );

  return algorithm.deriveKeyFromPassword(password: password, nonce: salt);
}

List<int> generateChacha20Nonce() {
  final cipher = Chacha20.poly1305Aead();

  return cipher.newNonce();
}

Stream<List<int>> encryptChacha20({
  required SecretKey secretKey,
  required List<int> nonce,
  required Stream<List<int>> inputStream,
  required void Function(Mac) onMac,
}) {
  final cipher = Chacha20.poly1305Aead();

  assert(nonce.length == cipher.nonceLength);

  return cipher.encryptStream(
    inputStream,
    secretKey: secretKey,
    nonce: nonce,
    onMac: onMac,
  );
}

Stream<List<int>> decryptChacha20({
  required SecretKey secretKey,
  required List<int> nonce,
  required FutureOr<Mac> mac,
  required Stream<List<int>> inputStream,
}) {
  final cipher = Chacha20.poly1305Aead();

  assert(nonce.length == cipher.nonceLength);

  return cipher.decryptStream(
    inputStream,
    secretKey: secretKey,
    nonce: nonce,
    mac: mac,
  );
}
