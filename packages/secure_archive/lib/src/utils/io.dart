// ignore_for_file: parameter_assignments

import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';

import 'package:collection/collection.dart';
import 'package:io/io.dart';
import 'package:path/path.dart' as p;
import 'package:pool/pool.dart';
import 'package:rxdart/rxdart.dart';
import 'package:secure_archive/src/utils/archive.dart';
import 'package:uuid/uuid.dart';

typedef ComputeCallback<M, R> = FutureOr<R> Function(M message);

/// Returns whether [link] exists on the file system.
///
/// This returns `true` for any symlink, regardless of what it points at or
/// whether it's broken.
bool linkExists(String link) => Link(link).existsSync();

/// Deletes [file] if it's a symlink.
///
/// The [File] class overwrites the symlink targets when writing to a file,
/// which is never what we want, so this delete the symlink first if necessary.
void deleteIfLink(String file) {
  if (!linkExists(file)) return;
  // log.io('Deleting symlink at $file.');
  Link(file).deleteSync();
}

/// Ensures that [dir] and all its parent directories exist.
///
/// If they don't exist, creates them.
String ensureDir(String dir) {
  Directory(dir).createSync(recursive: true);
  return dir;
}

/// Sanitizes the executable path on windows for [Process.start], [Process.run]
/// and [Process.runSync].
(String, List<String>) _sanitizeExecutablePath(
  String executable,
  List<String> args, {
  String? workingDir,
}) {
  // Spawning a process on Windows will not look for the executable in the
  // system path. So, if executable looks like it needs that (i.e. it doesn't
  // have any path separators in it), then spawn it through a shell.
  if (Platform.isWindows && !executable.contains('\\')) {
    args = ['/c', executable, ...args];
    executable = 'cmd';
  }

  // log.process(executable, args, workingDir ?? '.');
  return (executable, args);
}

/// Adaptation of ProcessResult when stdout is a `List<String>`.
class StringProcessResult {
  final String stdout;
  final String stderr;
  final int exitCode;
  StringProcessResult(this.stdout, this.stderr, this.exitCode);
  bool get success => exitCode == 0;
}

/// Like [runProcess], but synchronous.
StringProcessResult runProcessSync(
  String executable,
  List<String> args, {
  String? workingDir,
  Map<String, String>? environment,
  bool runInShell = false,
  Encoding stdoutEncoding = systemEncoding,
  Encoding stderrEncoding = systemEncoding,
}) {
  ArgumentError.checkNotNull(executable, 'executable');
  ProcessResult result;
  try {
    (executable, args) = _sanitizeExecutablePath(
      executable,
      args,
      workingDir: workingDir,
    );
    result = Process.runSync(
      executable,
      args,
      workingDirectory: workingDir,
      environment: environment,
      runInShell: runInShell,
      stdoutEncoding: stdoutEncoding,
      stderrEncoding: stderrEncoding,
    );
  } on IOException catch (e) {
    throw Exception('Failed to run subprocess `$executable`: $e');
  }
  // log.processResult(executable, result);
  return StringProcessResult(
    result.stdout as String,
    result.stderr as String,
    result.exitCode,
  );
}

/// Writes [stream] to a new file at path [file].
///
/// Replaces any file already at that path. Completes when the file is done
/// being written.
Future<String> createFileFromStream(
  Pool pool,
  Stream<List<int>> stream,
  String file,
) {
  // log.io('Creating $file from stream.');

  return pool.withResource(() async {
    deleteIfLink(file);
    await stream.pipe(File(file).openWrite());
    // log.fine('Created $file from stream.');
    return file;
  });
}

void chmod(int mode, String file) {
  runProcessSync('chmod', [mode.toRadixString(8), file]);
}

/// Returns the transitive target of [link] (if A links to B which links to C,
/// this will return C).
///
/// If [link] is part of a symlink loop (e.g. A links to B which links back to
/// A), this returns the path to the first repeated link (so
/// `transitiveTarget("A")` would return `"A"` and `transitiveTarget("A")` would
/// return `"B"`).
///
/// This accepts paths to non-links or broken links, and returns them as-is.
String _resolveLink(String link) {
  final seen = <String>{};
  while (linkExists(link) && seen.add(link)) {
    link = p.normalize(p.join(p.dirname(link), Link(link).targetSync()));
  }
  return link;
}

/// Returns the canonical path for [pathString].
///
/// This is the normalized, absolute path, with symlinks resolved. Broken or
/// recursive symlinks will not be fully resolved.
///
/// This doesn't require [pathString] to point to a path that exists on the
/// filesystem; nonexistent or unreadable path entries are treated as normal
/// directories.
String canonicalize(String pathString) {
  final seen = <String>{};
  var components = Queue<String>.from(
    p.split(p.normalize(p.absolute(pathString))),
  );

  // The canonical path, built incrementally as we iterate through [components].
  var newPath = components.removeFirst();

  // Move through the components of the path, resolving each one's symlinks as
  // necessary. A resolved component may also add new components that need to be
  // resolved in turn.
  while (components.isNotEmpty) {
    seen.add(p.join(newPath, p.joinAll(components)));
    final resolvedPath = _resolveLink(
      p.join(newPath, components.removeFirst()),
    );
    final relative = p.relative(resolvedPath, from: newPath);

    // If the resolved path of the component relative to `newPath` is just ".",
    // that means component was a symlink pointing to its parent directory. We
    // can safely ignore such components.
    if (relative == '.') continue;

    final relativeComponents = Queue<String>.from(p.split(relative));

    // If the resolved path is absolute relative to `newPath`, that means it's
    // on a different drive. We need to canonicalize the entire target of that
    // symlink again.
    if (p.isAbsolute(relative)) {
      // If we've already tried to canonicalize the new path, we've encountered
      // a symlink loop. Avoid going infinite by treating the recursive symlink
      // as the canonical path.
      if (seen.contains(relative)) {
        newPath = relative;
      } else {
        newPath = relativeComponents.removeFirst();
        relativeComponents.addAll(components);
        components = relativeComponents;
      }
      continue;
    }

    // Pop directories off `newPath` if the component links upwards in the
    // directory hierarchy.
    while (relativeComponents.firstOrNull == '..') {
      newPath = p.dirname(newPath);
      relativeComponents.removeFirst();
    }

    // If there's only one component left, [resolveLink] guarantees that it's
    // not a link (or is a broken link). We can just add it to `newPath` and
    // continue resolving the remaining components.
    if (relativeComponents.length == 1) {
      newPath = p.join(newPath, relativeComponents.single);
      continue;
    }

    // If we've already tried to canonicalize the new path, we've encountered a
    // symlink loop. Avoid going infinite by treating the recursive symlink as
    // the canonical path.
    final newSubPath = p.join(newPath, p.joinAll(relativeComponents));
    if (seen.contains(newSubPath)) {
      newPath = newSubPath;
      continue;
    }

    // If there are multiple new components to resolve, add them to the
    // beginning of the queue.
    relativeComponents.addAll(components);
    components = relativeComponents;
  }
  return newPath;
}

/// Creates a new symlink at path [symlink] that points to [target].
///
/// Returns a [Future] which completes to the path to the symlink file.
///
/// If [relative] is true, creates a symlink with a relative path from the
/// symlink to the target. Otherwise, uses the [target] path unmodified.
///
/// Note that on Windows, only directories may be symlinked to.
void createSymlink(String target, String symlink, {bool relative = false}) {
  if (relative) {
    // Relative junction points are not supported on Windows. Instead, just
    // make sure we have a clean absolute path because it will interpret a
    // relative path to be relative to the cwd, not the symlink, and will be
    // confused by forward slashes.
    if (Platform.isWindows) {
      target = p.normalize(p.absolute(target));
    } else {
      // If the directory where we're creating the symlink was itself reached
      // by traversing a symlink, we want the relative path to be relative to
      // it's actual location, not the one we went through to get to it.
      final symlinkDir = canonicalize(p.dirname(symlink));
      target = p.normalize(p.relative(target, from: symlinkDir));
    }
  }

  // log.fine('Creating $symlink pointing to $target');
  Link(symlink).createSync(target);
}

Directory getIntermediateDirectory() {
  return Directory(
    p.join(Directory.systemTemp.path, 'secure_archive', const Uuid().v4()),
  );
}

Future<T> withIntermediateDirectory<T>(
  FutureOr<T> Function(Directory dir) action, {
  bool createDirectory = true,
}) async {
  final dir = getIntermediateDirectory();
  if (createDirectory) {
    await dir.create(recursive: true);
  }

  try {
    return await action(dir);
  } finally {
    try {
      if (await dir.exists()) {
        await dir.delete(recursive: true);
      }
    } catch (_) {
      // Ignore cleanup errors
    }
  }
}

Future<bool> directoryEquals(
  Directory dirA,
  Directory dirB, {
  required bool recursive,
  required bool ignoreHidden,
}) async {
  final relativeFilesA = await listDirectoryFilesRelative(
    dirA,
    recursive: recursive,
    ignoreHidden: ignoreHidden,
  ).toList();

  final relativeFilesB = await listDirectoryFilesRelative(
    dirB,
    recursive: recursive,
    ignoreHidden: ignoreHidden,
  ).toList();

  if (!DeepCollectionEquality.unordered(
    EqualityBy<File, String>((e) => e.path),
  ).equals(relativeFilesA, relativeFilesB)) {
    return false;
  }

  for (final file in relativeFilesA) {
    final fileA = File(p.join(dirA.path, file.path));
    final fileB = File(p.join(dirB.path, file.path));

    if (!await SequenceEqualStream(
      fileA.openRead(),
      fileB.openRead(),
      dataEquals: const DeepCollectionEquality().equals,
    ).first) {
      return false;
    }
  }

  return true;
}

Future<void> moveDirectory(Directory source, Directory destination) async {
  try {
    // Try rename first (fast if same filesystem)
    await source.rename(destination.path);
  } catch (e) {
    // If rename fails, copy recursively then delete source
    await copyPath(source.path, destination.path);
    await source.delete(recursive: true);
  }
}

/// The dart:io implementation of [isolates.compute].
@pragma('vm:prefer-inline')
Future<R> compute<M, R>(
  ComputeCallback<M, R> callback,
  M message, {
  String? debugLabel,
}) {
  return Isolate.run<R>(() {
    return callback(message);
  }, debugName: debugLabel ?? 'compute');
}
