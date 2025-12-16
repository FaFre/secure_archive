import 'dart:async';
import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:secure_archive/src/data/archive.dart';
import 'package:secure_archive/src/data/argon2_params.dart';
import 'package:secure_archive/src/domain/archive.dart';
import 'package:secure_archive/src/utils/io.dart';
import 'package:test/test.dart';

void main() {
  test('raw archive', () async {
    final sourceDir = Directory(
      p.join(Directory.current.path, './test/fixtures'),
    );

    await withIntermediateDirectory((targetEncryptionDir) async {
      final targetDecryptionDir = getIntermediateDirectory();

      const password = "123456";
      final result = await archive(
        sourceDir: sourceDir,
        targetDir: targetEncryptionDir,
        maxSizeBytes: 4096,
        argon2Params: Argon2Params.memoryConstrained(),
        password: password,
        ignoreHidden: false,
      );

      expect(result.parts.length, equals(3));

      await unarchive(
        sourceDir: targetEncryptionDir,
        targetDir: targetDecryptionDir,
        argon2Params: Argon2Params.memoryConstrained(),
        password: password,
      );

      expect(
        await directoryEquals(
          sourceDir,
          targetDecryptionDir,
          recursive: true,
          ignoreHidden: false,
        ),
        equals(true),
      );
    });
  });

  test('packed archive', () async {
    const password = "123456";

    final sourceDir = Directory(
      p.join(Directory.current.path, './test/fixtures'),
    );

    await withIntermediateDirectory((archiveDir) async {
      final archiveFile = File(p.join(archiveDir.path, 'output.tar'));

      final archivePack = SecureArchivePack(
        sourceDirectory: sourceDir,
        outputFile: archiveFile,
        argon2Params: Argon2Params.memoryConstrained(),
      );
      await archivePack.pack(
        password,
        // ignore: avoid_redundant_argument_values
        ignoreHidden: false,
        integrityCheck: true,
      );

      final unpackDir = getIntermediateDirectory();
      final archiveUnpack = SecureArchiveUnpack(
        inputFile: archiveFile,
        outputDirectory: unpackDir,
        argon2Params: Argon2Params.memoryConstrained(),
      );
      await archiveUnpack.unpack(password);

      expect(
        await directoryEquals(
          sourceDir,
          unpackDir,
          recursive: true,
          ignoreHidden: false,
        ),
        equals(true),
      );
    });
  });

  test('extract valid archive', () async {
    const password = "123456";
    final archiveFile = File(
      p.join(Directory.current.path, './test/archives', 'valid_archive.tar'),
    );

    final unpackDir = getIntermediateDirectory();
    final archiveUnpack = SecureArchiveUnpack(
      inputFile: archiveFile,
      outputDirectory: unpackDir,
      argon2Params: Argon2Params.memoryConstrained(),
    );

    await expectLater(() => archiveUnpack.unpack(password), returnsNormally);
  });

  test('test integrity', () async {
    final sourceDir = Directory(
      p.join(Directory.current.path, './test/fixtures'),
    );

    const password = "123456";
    final archiveFile = File(
      p.join(Directory.current.path, './test/archives', 'valid_archive.tar'),
    );

    final archiveIntegrity = SecureArchiveIntegrity(
      archiveFile: archiveFile,
      sourceDirectory: sourceDir,
      argon2Params: Argon2Params.memoryConstrained(),
    );

    expect(await archiveIntegrity.checkIntegrity(password), equals(false));
  });

  test('invalid password valid archive', () async {
    const password = "wrong_pw";
    final archiveFile = File(
      p.join(Directory.current.path, './test/archives', 'valid_archive.tar'),
    );

    final unpackDir = getIntermediateDirectory();
    final archiveUnpack = SecureArchiveUnpack(
      inputFile: archiveFile,
      outputDirectory: unpackDir,
      argon2Params: Argon2Params.memoryConstrained(),
    );

    final throws = Completer<bool>();
    unawaited(
      runZonedGuarded(
        () async {
          await archiveUnpack.unpack(password);
          throws.complete(false);
        },
        (error, stack) {
          if (!throws.isCompleted) {
            throws.complete(true);
          }
        },
      ),
    );

    if (!await throws.future) {
      fail('Expected Exception due to invalid password');
    }
  });

  test('extract tampered archive', () {
    const password = "123456";
    final archiveFile = File(
      p.join(Directory.current.path, './test/archives', 'tampered_archive.tar'),
    );

    final unpackDir = getIntermediateDirectory();
    final archiveUnpack = SecureArchiveUnpack(
      inputFile: archiveFile,
      outputDirectory: unpackDir,
      argon2Params: Argon2Params.memoryConstrained(),
    );
    expect(() => archiveUnpack.unpack(password), throwsA(isA<Exception>()));
  });
}
