import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:secure_archive/src/utils/archive.dart';
import 'package:test/test.dart';

void main() {
  test('split directory test', () async {
    final entries = findFileEntries(
      Directory(p.join(Directory.current.path, './test/fixtures')),
      ignoreHidden: false,
    );
    final splitStreams = splitTarEntriesBySize(entries, 4096);

    final tarChunks = await splitStreams.toList();

    expect(tarChunks.length, equals(3));

    final first = await tarChunks[0].toList();
    final second = await tarChunks[1].toList();
    final third = await tarChunks[2].toList();

    expect(first.length, equals(1));
    expect(second.length, equals(1));
    expect(third.length, equals(2));
  });
}
