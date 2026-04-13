import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:secure_archive/src/data/archive.dart';
import 'package:secure_archive/src/data/argon2_params.dart';
import 'package:secure_archive/src/data/models/archive_metadata.dart';
import 'package:secure_archive/src/utils/archive.dart';
import 'package:secure_archive/src/utils/io.dart';
import 'package:tar/tar.dart';

// Data classes for passing parameters to isolates
class _PackParams {
  final String sourceDirPath;
  final String intermediateDirPath;
  final Argon2Params argon2Params;
  final String password;
  final int softChunkLimit;
  final bool ignoreHidden;

  _PackParams({
    required this.sourceDirPath,
    required this.intermediateDirPath,
    required this.argon2Params,
    required this.password,
    required this.softChunkLimit,
    required this.ignoreHidden,
  });
}

class _UnpackParams {
  final String inputFilePath;
  final String intermediateDirPath;
  final String outputDirPath;
  final Argon2Params argon2Params;
  final String password;

  _UnpackParams({
    required this.inputFilePath,
    required this.intermediateDirPath,
    required this.outputDirPath,
    required this.argon2Params,
    required this.password,
  });
}

class _TarParams {
  final String intermediateDirPath;
  final String outputFilePath;
  final bool ignoreHidden;

  _TarParams({
    required this.intermediateDirPath,
    required this.outputFilePath,
    required this.ignoreHidden,
  });
}

class _DirectoryEqualityParams {
  final String dirA;
  final String dirB;
  final bool recursive;
  final bool ignoreHidden;

  _DirectoryEqualityParams({
    required this.dirA,
    required this.dirB,
    required this.recursive,
    required this.ignoreHidden,
  });
}

Future<ArchiveMetadata> _archiveInIsolate(_PackParams params) async {
  return await archive(
    sourceDir: Directory(params.sourceDirPath),
    targetDir: Directory(params.intermediateDirPath),
    maxSizeBytes: params.softChunkLimit,
    ignoreHidden: params.ignoreHidden,
    argon2Params: params.argon2Params,
    password: params.password,
  );
}

Future<void> _createTarInIsolate(_TarParams params) async {
  await findFileEntries(
    Directory(params.intermediateDirPath),
    ignoreHidden: params.ignoreHidden,
  ).transform(tarWriter).pipe(File(params.outputFilePath).openWrite());
}

Future<void> _extractTarInIsolate(_UnpackParams params) async {
  await extractTar(
    File(params.inputFilePath).openRead(),
    params.intermediateDirPath,
  );
}

Future<void> _unarchiveInIsolate(_UnpackParams params) async {
  await unarchive(
    sourceDir: Directory(params.intermediateDirPath),
    targetDir: Directory(params.outputDirPath),
    argon2Params: params.argon2Params,
    password: params.password,
  );
}

Future<bool> _directoryEqualsInIsolate(_DirectoryEqualityParams params) async {
  final equals = await directoryEquals(
    Directory(params.dirA),
    Directory(params.dirB),
    ignoreHidden: params.ignoreHidden,
    recursive: params.recursive,
  );

  return equals;
}

class SecureArchiveIntegrity {
  final File archiveFile;
  final Directory sourceDirectory;
  final Argon2Params argon2Params;

  SecureArchiveIntegrity({
    required this.archiveFile,
    required this.sourceDirectory,
    required this.argon2Params,
  });

  Future<bool> checkIntegrity(
    String password, {
    bool ignoreHidden = false,
  }) async {
    return await withIntermediateDirectory((outputDirectory) async {
      return await withIntermediateDirectory((intermediateDir) async {
        final params = _UnpackParams(
          inputFilePath: archiveFile.path,
          intermediateDirPath: intermediateDir.path,
          outputDirPath: outputDirectory.path,
          argon2Params: argon2Params,
          password: password,
        );

        await compute(_extractTarInIsolate, params);
        await compute(_unarchiveInIsolate, params);

        final integrity = await compute(
          _directoryEqualsInIsolate,
          _DirectoryEqualityParams(
            dirA: sourceDirectory.path,
            dirB: outputDirectory.path,
            recursive: true,
            ignoreHidden: ignoreHidden,
          ),
        );

        return integrity;
      });
    }, createDirectory: false);
  }
}

class SecureArchivePack {
  final File outputFile;
  final Directory sourceDirectory;
  final Argon2Params argon2Params;

  SecureArchivePack({
    required this.outputFile,
    required this.sourceDirectory,
    required this.argon2Params,
  });

  Future<void> pack(
    String password, {
    required bool integrityCheck,
    int softChunkLimit = 100 * 1024 * 1024,
    bool ignoreHidden = false,
  }) async {
    await withIntermediateDirectory((stagingDir) async {
      final stagedOutput = File(p.join(stagingDir.path, 'archive.sa'));

      await withIntermediateDirectory((intermediateDir) async {
        final metadata = await compute(
          _archiveInIsolate,
          _PackParams(
            sourceDirPath: sourceDirectory.path,
            intermediateDirPath: intermediateDir.path,
            argon2Params: argon2Params,
            password: password,
            softChunkLimit: softChunkLimit,
            ignoreHidden: ignoreHidden,
          ),
        );

        final createdFiles = await intermediateDir.list().length;
        if (createdFiles != metadata.parts.length + 1) {
          throw Exception('Corrupt output');
        }

        await compute(
          _createTarInIsolate,
          _TarParams(
            intermediateDirPath: intermediateDir.path,
            outputFilePath: stagedOutput.path,
            ignoreHidden: ignoreHidden,
          ),
        );
      });

      if (integrityCheck) {
        final archiveIntegrity = SecureArchiveIntegrity(
          archiveFile: stagedOutput,
          sourceDirectory: sourceDirectory,
          argon2Params: argon2Params,
        );

        final result = await archiveIntegrity.checkIntegrity(
          password,
          ignoreHidden: ignoreHidden,
        );
        if (!result) {
          throw Exception('Could not validate backup integrity');
        }
      }

      await outputFile.parent.create(recursive: true);
      await stagedOutput.copy(outputFile.path);
    });
  }
}

class SecureArchiveUnpack {
  final File inputFile;
  final Directory outputDirectory;
  final Argon2Params argon2Params;

  SecureArchiveUnpack({
    required this.inputFile,
    required this.outputDirectory,
    required this.argon2Params,
  });

  Future<void> unpack(String password) async {
    await withIntermediateDirectory((intermediateDir) async {
      final params = _UnpackParams(
        inputFilePath: inputFile.path,
        intermediateDirPath: intermediateDir.path,
        outputDirPath: outputDirectory.path,
        argon2Params: argon2Params,
        password: password,
      );

      await compute(_extractTarInIsolate, params);
      await compute(_unarchiveInIsolate, params);
    });
  }
}
