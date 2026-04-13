import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';

import 'package:path/path.dart' as p;
import 'package:secure_archive/src/data/archive.dart';
import 'package:secure_archive/src/data/argon2_params.dart';
import 'package:secure_archive/src/domain/archive.dart';
import 'package:secure_archive/src/utils/archive.dart';
import 'package:secure_archive/src/utils/io.dart';
import 'package:tar/tar.dart';
import 'package:test/test.dart';

Future<void> _writeTextFile(String path, String contents) async {
  final file = File(path);
  await file.parent.create(recursive: true);
  await file.writeAsString(contents);
}

Stream<List<int>> _textContents(String contents) {
  return Stream<List<int>>.value(utf8.encode(contents));
}

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

  test('extract tar with explicit directory entry', () async {
    await withIntermediateDirectory((destination) async {
      const contents = 'hello';
      final tarStream = Stream<TarEntry>.fromIterable([
        TarEntry(
          TarHeader(name: 'nested', typeFlag: TypeFlag.dir, mode: 493),
          const Stream.empty(),
        ),
        TarEntry(
          TarHeader(
            name: 'nested/file.txt',
            typeFlag: TypeFlag.reg,
            mode: 420,
            size: contents.length,
          ),
          _textContents(contents),
        ),
      ]).transform(tarWriter);

      await extractTar(tarStream, destination.path);

      expect(
        await File(
          p.join(destination.path, 'nested', 'file.txt'),
        ).readAsString(),
        contents,
      );
    });
  });

  test('extract tar with symlink entry', () async {
    if (Platform.isWindows) {
      return;
    }

    await withIntermediateDirectory((destination) async {
      const contents = 'hello';
      final tarStream = Stream<TarEntry>.fromIterable([
        TarEntry(
          TarHeader(
            name: 'source.txt',
            typeFlag: TypeFlag.reg,
            mode: 420,
            size: 5,
          ),
          _textContents(contents),
        ),
        TarEntry(
          TarHeader(
            name: 'alias.txt',
            typeFlag: TypeFlag.symlink,
            mode: 493,
            linkName: 'source.txt',
          ),
          const Stream.empty(),
        ),
      ]).transform(tarWriter);

      await extractTar(tarStream, destination.path);

      final alias = Link(p.join(destination.path, 'alias.txt'));
      expect(await alias.exists(), isTrue);
      expect(await alias.target(), 'source.txt');
    });
  });

  test(
    'extract tar rejects writes through symlinked parent directory',
    () async {
      if (Platform.isWindows) {
        return;
      }

      await withIntermediateDirectory((workspaceDir) async {
        final destinationDir = Directory(
          p.join(workspaceDir.path, 'destination'),
        );
        await destinationDir.create(recursive: true);

        final outsideDir = Directory(p.join(workspaceDir.path, 'outside'));
        await outsideDir.create(recursive: true);
        await Link(
          p.join(destinationDir.path, 'linked'),
        ).create(outsideDir.path);

        final tarStream = Stream<TarEntry>.fromIterable([
          TarEntry(
            TarHeader(
              name: 'linked/escape.txt',
              typeFlag: TypeFlag.reg,
              mode: 420,
              size: 6,
            ),
            _textContents('escape'),
          ),
        ]).transform(tarWriter);

        await expectLater(
          extractTar(tarStream, destinationDir.path),
          throwsA(isA<FormatException>()),
        );
        expect(
          File(p.join(outsideDir.path, 'escape.txt')).existsSync(),
          isFalse,
        );
      });
    },
  );

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

  test('packed archive integrity respects ignoreHidden', () async {
    const password = '123456';

    await withIntermediateDirectory((sourceDir) async {
      await _writeTextFile(p.join(sourceDir.path, 'visible.txt'), 'visible');
      await _writeTextFile(p.join(sourceDir.path, '.hidden.txt'), 'hidden');

      await withIntermediateDirectory((archiveDir) async {
        final archiveFile = File(p.join(archiveDir.path, 'output.tar'));
        final archivePack = SecureArchivePack(
          sourceDirectory: sourceDir,
          outputFile: archiveFile,
          argon2Params: Argon2Params.memoryConstrained(),
        );

        await archivePack.pack(
          password,
          integrityCheck: true,
          ignoreHidden: true,
        );
      });
    });
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

    await expectLater(
      archiveUnpack.unpack(password),
      throwsA(anyOf(isA<Exception>(), isA<RemoteError>())),
    );
  });

  test('listing files does not follow directory symlinks', () async {
    if (Platform.isWindows) {
      return;
    }

    await withIntermediateDirectory((workspaceDir) async {
      final sourceDir = Directory(p.join(workspaceDir.path, 'source'));
      final outsideDir = Directory(p.join(workspaceDir.path, 'outside'));
      await sourceDir.create(recursive: true);
      await outsideDir.create(recursive: true);

      await _writeTextFile(p.join(sourceDir.path, 'visible.txt'), 'visible');
      await _writeTextFile(p.join(outsideDir.path, 'secret.txt'), 'secret');

      await Link(p.join(sourceDir.path, 'linked-dir')).create(outsideDir.path);

      final listedFiles = await listDirectoryFilesRelative(
        sourceDir,
        recursive: true,
        ignoreHidden: false,
      ).map((file) => file.path).toList();

      expect(listedFiles, contains('visible.txt'));
      expect(listedFiles.any((file) => file.contains('secret.txt')), isFalse);
    });
  });

  test('packed archive includes file symlinks', () async {
    if (Platform.isWindows) {
      return;
    }

    const password = '123456';

    await withIntermediateDirectory((sourceDir) async {
      await _writeTextFile(p.join(sourceDir.path, 'source.txt'), 'hello');
      await Link(
        p.join(sourceDir.path, 'alias.txt'),
      ).create(p.join(sourceDir.path, 'source.txt'));

      await withIntermediateDirectory((archiveDir) async {
        final archiveFile = File(p.join(archiveDir.path, 'output.tar'));
        final archivePack = SecureArchivePack(
          sourceDirectory: sourceDir,
          outputFile: archiveFile,
          argon2Params: Argon2Params.memoryConstrained(),
        );

        await archivePack.pack(password, integrityCheck: true);

        final unpackDir = getIntermediateDirectory();
        final archiveUnpack = SecureArchiveUnpack(
          inputFile: archiveFile,
          outputDirectory: unpackDir,
          argon2Params: Argon2Params.memoryConstrained(),
        );

        await archiveUnpack.unpack(password);

        expect(
          await File(p.join(unpackDir.path, 'alias.txt')).readAsString(),
          'hello',
        );
      });
    });
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
