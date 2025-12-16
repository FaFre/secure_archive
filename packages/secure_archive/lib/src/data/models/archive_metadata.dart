import 'package:json_annotation/json_annotation.dart';
import 'package:secure_archive/src/data/converters/base64_converter.dart';
import 'package:secure_archive/src/data/models/encryption_result.dart';

part 'archive_metadata.g.dart';

@JsonSerializable()
class ArchiveMetadata {
  final int version;
  @Base64Converter()
  final List<int> salt;
  final Map<int, EncryptionResult> parts;

  ArchiveMetadata({
    required this.version,
    required this.salt,
    required this.parts,
  });

  factory ArchiveMetadata.fromJson(Map<String, dynamic> json) =>
      _$ArchiveMetadataFromJson(json);

  Map<String, dynamic> toJson() => _$ArchiveMetadataToJson(this);
}
