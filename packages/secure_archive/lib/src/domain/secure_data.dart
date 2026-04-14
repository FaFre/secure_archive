import 'package:secure_archive/src/data/argon2_params.dart';
import 'package:secure_archive/src/data/secure_data.dart';
import 'package:secure_archive/src/utils/io.dart';

class _EncryptParams {
  final List<int> data;
  final String password;
  final Argon2Params argon2Params;
  final bool compress;

  _EncryptParams({
    required this.data,
    required this.password,
    required this.argon2Params,
    required this.compress,
  });
}

class _DecryptParams {
  final List<int> data;
  final String password;
  final Argon2Params argon2Params;

  _DecryptParams({
    required this.data,
    required this.password,
    required this.argon2Params,
  });
}

Future<List<int>> _encryptInIsolate(_EncryptParams params) {
  return encryptData(
    data: params.data,
    password: params.password,
    argon2Params: params.argon2Params,
    compress: params.compress,
  );
}

Future<List<int>> _decryptInIsolate(_DecryptParams params) {
  return decryptData(
    data: params.data,
    password: params.password,
    argon2Params: params.argon2Params,
  );
}

class SecureData {
  final Argon2Params argon2Params;

  SecureData({required this.argon2Params});

  /// Encrypts [data] with [password].
  ///
  /// Returns a self-contained blob that includes all metadata needed for
  /// decryption (salt, nonce, MAC). Set [compress] to gzip the data before
  /// encryption.
  Future<List<int>> encrypt(
    List<int> data,
    String password, {
    bool compress = false,
  }) {
    return compute(
      _encryptInIsolate,
      _EncryptParams(
        data: data,
        password: password,
        argon2Params: argon2Params,
        compress: compress,
      ),
    );
  }

  /// Decrypts a blob previously produced by [encrypt].
  ///
  /// Compression is detected automatically from the header flags.
  /// Throws if the password is wrong or the data is corrupted.
  Future<List<int>> decrypt(List<int> data, String password) {
    return compute(
      _decryptInIsolate,
      _DecryptParams(
        data: data,
        password: password,
        argon2Params: argon2Params,
      ),
    );
  }
}
