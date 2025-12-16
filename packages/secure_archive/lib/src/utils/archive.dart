import 'dart:async';
import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:pool/pool.dart';
import 'package:secure_archive/src/utils/io.dart';
import 'package:tar/tar.dart';

/// The pool used for restricting access to asynchronous operations that consume
/// file descriptors.
///
/// The maximum number of allocated descriptors is based on empirical tests that
/// indicate that beyond 32, additional file reads don't provide substantial
/// additional throughput.
final _descriptorPool = Pool(32);

/// The assumed default file mode on Linux and macOS
const _defaultMode = 420; // 644₈

/// Mask for executable bits in file modes.
const _executableMask = 0x49; // 001 001 001

Stream<File> listDirectoryFilesRelative(
  Directory root, {
  required bool recursive,
  required bool ignoreHidden,
}) async* {
  await for (final entry in root.list(recursive: recursive)) {
    if (entry is! File) continue;

    final relativePath = p.relative(entry.path, from: root.path);

    if (ignoreHidden) {
      // Skip hidden files/directories at any level
      if (relativePath.split(p.separator).any((part) => part.startsWith('.'))) {
        continue;
      }
    }

    yield File(relativePath);
  }
}

Stream<TarEntry> findFileEntries(
  Directory root, {
  required bool ignoreHidden,
}) async* {
  await for (final relativeFile in listDirectoryFilesRelative(
    root,
    recursive: true,
    ignoreHidden: ignoreHidden,
  )) {
    try {
      final file = File(p.join(root.path, relativeFile.path));
      final stat = await file.stat();

      yield TarEntry(
        TarHeader(
          name: relativeFile.path,
          typeFlag: TypeFlag.reg, // It's a regular file
          // Apart from that, copy over meta information
          mode: stat.mode,
          modified: stat.modified,
          accessed: stat.accessed,
          changed: stat.changed,
          // This assumes that the file won't change until we're writing it into
          // the archive later, since then the size might be wrong. It's more
          // efficient though, since the tar writer would otherwise have to buffer
          // everything to find out the size.
          size: stat.size,
        ),
        // Use entry.openRead() to obtain an input stream for the file that the
        // writer will use later.
        file.openRead(),
      );
    } catch (e) {
      // File was deleted or became inaccessible - skip it
      continue;
    }
  }
}

/// Splits a stream of TarEntry into multiple streams based on size limit
Stream<Stream<TarEntry>> splitTarEntriesBySize(
  Stream<TarEntry> entries,
  int maxSizeBytes,
) {
  return entries.transform(
    StreamTransformer.fromBind((stream) {
      final controller = StreamController<Stream<TarEntry>>();

      StreamController<TarEntry>? currentChunk;
      int currentSize = 0;

      void startNewChunk() {
        currentChunk = StreamController<TarEntry>();
        currentSize = 0;
        controller.add(currentChunk!.stream);
      }

      stream.listen(
        (entry) {
          final entrySize = entry.header.size;

          if (currentChunk == null) {
            startNewChunk();
          } else if (currentSize > 0 &&
              currentSize + entrySize > maxSizeBytes) {
            unawaited(currentChunk?.close());
            startNewChunk();
          }

          currentChunk!.add(entry);
          currentSize += entrySize;
        },
        onError: (Object error) {
          currentChunk?.addError(error);
          controller.addError(error);
        },
        onDone: () {
          unawaited(currentChunk?.close());
          unawaited(controller.close());
        },
        cancelOnError: false,
      );

      return controller.stream;
    }),
  );
}

/// Extracts a `.tar` file from [stream] to [destination].
Future<void> extractTar(Stream<List<int>> stream, String destination) async {
  // log.fine('Extracting .tar stream to $destination.');

  // ignore: parameter_assignments
  destination = p.absolute(destination);
  final reader = TarReader(stream);
  final paths = <String>{};
  while (await reader.moveNext()) {
    final entry = reader.current;

    final filePath = p.joinAll([
      destination,
      // Tar file names always use forward slashes
      ...p.posix.split(entry.name),
    ]);
    if (!paths.add(filePath)) {
      // The tar file contained the same entry twice. Assume it is broken.
      await reader.cancel();
      throw FormatException('Tar file contained duplicate path ${entry.name}');
    }

    if (!(p.isWithin(destination, filePath) ||
        // allow including '.' as an entry in the tar archive.
        (entry.type == TypeFlag.dir && p.equals(destination, filePath)))) {
      // The tar contains entries that would be written outside of the
      // destination. That doesn't happen by accident, assume that the tar file
      // is malicious.
      await reader.cancel();
      throw FormatException('Invalid tar entry: `${entry.name}`');
    }

    final parentDirectory = p.dirname(filePath);

    bool checkValidTarget(String linkTarget) {
      final isValid = p.isWithin(destination, linkTarget);
      if (!isValid) {
        // log.fine('Skipping ${entry.name}: Invalid link target');
      }

      return isValid;
    }

    switch (entry.type) {
      case TypeFlag.dir:
        ensureDir(filePath);
      case TypeFlag.reg:
      case TypeFlag.regA:
        // Regular file
        deleteIfLink(filePath);
        ensureDir(parentDirectory);
        await createFileFromStream(_descriptorPool, entry.contents, filePath);

        if (Platform.isLinux || Platform.isMacOS) {
          // Apply executable bits from tar header, but don't change r/w bits
          // from the default
          final mode = _defaultMode | (entry.header.mode & _executableMask);

          if (mode != _defaultMode) {
            chmod(mode, filePath);
          }
        }
      case TypeFlag.symlink:
        // Link to another file in this tar, relative from this entry.
        final resolvedTarget = p.joinAll([
          parentDirectory,
          ...p.posix.split(entry.header.linkName!),
        ]);
        if (!checkValidTarget(resolvedTarget)) {
          // Don't allow links to files outside of this tar.
          break;
        }

        ensureDir(parentDirectory);
        createSymlink(
          p.relative(resolvedTarget, from: parentDirectory),
          filePath,
        );
      case TypeFlag.link:
        // We generate hardlinks as symlinks too, but their linkName is relative
        // to the root of the tar file (unlike symlink entries, whose linkName
        // is relative to the entry itself).
        final fromDestination = p.join(destination, entry.header.linkName);
        if (!checkValidTarget(fromDestination)) {
          break; // Link points outside of the tar file.
        }

        final fromFile = p.relative(fromDestination, from: parentDirectory);
        ensureDir(parentDirectory);
        createSymlink(fromFile, filePath);
      default:
        // Only extract files
        continue;
    }
  }

  // log.fine('Extracted .tar to $destination.');
}
