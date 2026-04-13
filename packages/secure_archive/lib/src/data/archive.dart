import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:path/path.dart' as p;
import 'package:secure_archive/src/data/argon2_params.dart';
import 'package:secure_archive/src/data/models/archive_metadata.dart';
import 'package:secure_archive/src/data/models/encryption_result.dart';
import 'package:secure_archive/src/utils/archive.dart';
import 'package:secure_archive/src/utils/crypto.dart';
import 'package:secure_archive/src/utils/io.dart';
import 'package:tar/tar.dart';

Future<ArchiveMetadata> archive({
  required Directory sourceDir,
  required Directory targetDir,
  required int maxSizeBytes,
  required Argon2Params argon2Params,
  required String password,
  required bool ignoreHidden,
}) async {
  // Validation
  if (!await sourceDir.exists()) {
    throw ArgumentError('Source directory does not exist: ${sourceDir.path}');
  }
  if (maxSizeBytes <= 0) {
    throw ArgumentError('maxSizeBytes must be positive');
  }
  if (password.isEmpty) {
    throw ArgumentError('Password cannot be empty');
  }

  await targetDir.create(recursive: true);

  final directoryEntriesStream = findFileEntries(
    sourceDir,
    ignoreHidden: ignoreHidden,
  );
  final chunkStream = splitTarEntriesBySize(
    directoryEntriesStream,
    maxSizeBytes,
  );

  final salt = generateRandomBytes(16);
  final secretKey = await deriveArgon2idKey(argon2Params, password, salt);

  int chunkCount = 1;
  final parts = <int, EncryptionResult>{};
  final createdFiles = <File>[];

  try {
    await for (final chunk in chunkStream) {
      final nonce = generateChacha20Nonce();
      final currentPart = chunkCount++;
      final macCompleter = Completer<Mac>();

      final outputFile = File(
        p.join(
          targetDir.path,
          'archive.${currentPart.toString().padLeft(3, '0')}',
        ),
      );
      createdFiles.add(outputFile);

      final fileSink = outputFile.openWrite();
      try {
        final encryptionStream = encryptChacha20(
          secretKey: secretKey,
          nonce: nonce,
          inputStream: chunk.transform(tarWriter).transform(gzip.encoder),
          onMac: macCompleter.complete,
        );

        await for (final chunk in encryptionStream) {
          fileSink.add(chunk);
        }

        final mac = await macCompleter.future;
        parts[currentPart] = EncryptionResult(nonce: nonce, mac: mac.bytes);
      } catch (e) {
        throw Exception('Failed to create archive part $currentPart: $e');
      } finally {
        await fileSink.close();
      }
    }

    // Write metadata only after all parts succeed
    final metadata = ArchiveMetadata(version: 1, salt: salt, parts: parts);
    final metadataFile = File(p.join(targetDir.path, 'metadata.json'));

    await metadataFile.writeAsString(
      jsonEncode(metadata.toJson()),
      flush: true,
    );
    createdFiles.add(metadataFile);

    return metadata;
  } catch (e) {
    // Clean up all created files on any failure
    for (final file in createdFiles) {
      try {
        if (await file.exists()) {
          await file.delete();
        }
      } catch (_) {
        // Ignore cleanup errors
      }
    }
    rethrow;
  }
}

Future<void> unarchive({
  required Directory sourceDir,
  required Directory targetDir,
  required Argon2Params argon2Params,
  required String password,
}) async {
  // Validation
  if (!await sourceDir.exists()) {
    throw ArgumentError('Source directory does not exist: ${sourceDir.path}');
  }
  if (await targetDir.exists()) {
    throw ArgumentError('Target directory already exists: ${targetDir.path}');
  }
  if (password.isEmpty) {
    throw ArgumentError('Password cannot be empty');
  }

  final metadataFile = File(p.join(sourceDir.path, 'metadata.json'));
  if (!await metadataFile.exists()) {
    throw ArgumentError('Metadata file not found');
  }

  final metadata = await metadataFile.readAsString().then(
    (content) =>
        ArchiveMetadata.fromJson(jsonDecode(content) as Map<String, dynamic>),
  );

  final secretKey = await deriveArgon2idKey(
    argon2Params,
    password,
    Uint8List.fromList(metadata.salt),
  );

  await withIntermediateDirectory((tempDir) async {
    for (final MapEntry(key: currentPart, value: encryptionResult)
        in metadata.parts.entries) {
      final inputFile = File(
        p.join(
          sourceDir.path,
          'archive.${currentPart.toString().padLeft(3, '0')}',
        ),
      );

      if (!await inputFile.exists()) {
        throw Exception('Archive part $currentPart not found');
      }

      final decryptController = StreamController<List<int>>();
      Future<void>? extractFuture;

      Future<void> waitForExtract() async {
        if (extractFuture == null) {
          return;
        }

        await extractFuture;
      }

      try {
        final decryptStream = decryptChacha20(
          secretKey: secretKey,
          nonce: encryptionResult.nonce,
          mac: Mac(encryptionResult.mac),
          inputStream: inputFile.openRead(),
        );

        extractFuture = extractTar(
          decryptController.stream.transform(gzip.decoder),
          tempDir.path,
        );

        await for (final chunk in decryptStream) {
          decryptController.add(chunk);
        }

        await decryptController.close();
        await waitForExtract();
      } on SecretBoxAuthenticationError {
        await decryptController.close();
        try {
          await waitForExtract();
        } catch (_) {
          // Authentication failure is the actionable error for callers.
        }

        throw Exception(
          'Authentication failed for part $currentPart: wrong password or corrupted data',
        );
      } catch (e) {
        await decryptController.close();
        try {
          await waitForExtract();
        } catch (_) {
          // Preserve the original extraction failure below.
        }

        throw Exception('Failed to extract part $currentPart: $e');
      }
    }

    await moveDirectory(tempDir, targetDir);
  });
}
