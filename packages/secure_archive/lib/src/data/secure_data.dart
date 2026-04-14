import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:secure_archive/src/data/argon2_params.dart';
import 'package:secure_archive/src/utils/crypto.dart';

/// Wire format:
/// [version: 1B] [flags: 1B] [salt: 16B] [nonce: 12B] [ciphertext: NB] [mac: 16B]
///
/// Flags: bit 0 = gzip compressed.

const _headerSize = 1 + 1 + 16 + 12; // 30 bytes
const _macSize = 16;
const _minBlobSize = _headerSize + _macSize; // 46 bytes, empty plaintext

const _version = 1;
const _flagGzip = 1 << 0;

Future<List<int>> encryptData({
  required List<int> data,
  required String password,
  required Argon2Params argon2Params,
  required bool compress,
}) async {
  if (password.isEmpty) {
    throw ArgumentError('Password cannot be empty');
  }

  final salt = generateRandomBytes(16);
  final secretKey = await deriveArgon2idKey(argon2Params, password, salt);
  final nonce = generateChacha20Nonce();

  List<int> payload = data;
  int flags = 0;

  if (compress) {
    payload = gzip.encode(data);
    flags |= _flagGzip;
  }

  // Build header before encryption so it can be used as AAD.
  final header = Uint8List(_headerSize);
  header[0] = _version;
  header[1] = flags;
  header.setRange(2, 18, salt);
  header.setRange(18, 30, nonce);

  final macCompleter = Completer<Mac>();
  final cipherChunks = <List<int>>[];

  final encryptionStream = encryptChacha20(
    secretKey: secretKey,
    nonce: nonce,
    inputStream: Stream.value(payload),
    onMac: macCompleter.complete,
    aad: header,
  );

  await for (final chunk in encryptionStream) {
    cipherChunks.add(chunk);
  }

  final mac = await macCompleter.future;

  final ciphertextLength = cipherChunks.fold<int>(
    0,
    (sum, chunk) => sum + chunk.length,
  );
  final result = Uint8List(_headerSize + ciphertextLength + _macSize);

  // Header
  result.setRange(0, _headerSize, header);

  // Ciphertext
  var offset = _headerSize;
  for (final chunk in cipherChunks) {
    result.setRange(offset, offset + chunk.length, chunk);
    offset += chunk.length;
  }

  // MAC
  result.setRange(offset, offset + _macSize, mac.bytes);

  return result;
}

Future<List<int>> decryptData({
  required List<int> data,
  required String password,
  required Argon2Params argon2Params,
}) async {
  if (password.isEmpty) {
    throw ArgumentError('Password cannot be empty');
  }
  if (data.length < _minBlobSize) {
    throw FormatException(
      'Data too short: expected at least $_minBlobSize bytes, got ${data.length}',
    );
  }

  final bytes = data is Uint8List ? data : Uint8List.fromList(data);

  final version = bytes[0];
  if (version != _version) {
    throw FormatException('Unsupported version: $version');
  }

  final flags = bytes[1];
  final compressed = (flags & _flagGzip) != 0;

  final header = Uint8List.sublistView(bytes, 0, _headerSize);
  final salt = Uint8List.sublistView(bytes, 2, 18);
  final nonce = Uint8List.sublistView(bytes, 18, 30);
  final ciphertext = Uint8List.sublistView(
    bytes,
    _headerSize,
    bytes.length - _macSize,
  );
  final mac = Mac(Uint8List.sublistView(bytes, bytes.length - _macSize));

  final secretKey = await deriveArgon2idKey(argon2Params, password, salt);

  final plainChunks = <List<int>>[];

  try {
    final decryptionStream = decryptChacha20(
      secretKey: secretKey,
      nonce: nonce,
      mac: mac,
      inputStream: Stream.value(ciphertext),
      aad: header,
    );

    await for (final chunk in decryptionStream) {
      plainChunks.add(chunk);
    }
  } on SecretBoxAuthenticationError {
    throw Exception('Decryption failed: wrong password or corrupted data');
  }

  final plaintext = Uint8List(
    plainChunks.fold<int>(0, (sum, chunk) => sum + chunk.length),
  );
  var offset = 0;
  for (final chunk in plainChunks) {
    plaintext.setRange(offset, offset + chunk.length, chunk);
    offset += chunk.length;
  }

  if (compressed) {
    return gzip.decode(plaintext);
  }

  return plaintext;
}
