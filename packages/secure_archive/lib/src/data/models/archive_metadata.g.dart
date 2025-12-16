// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'archive_metadata.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

ArchiveMetadata _$ArchiveMetadataFromJson(Map<String, dynamic> json) =>
    ArchiveMetadata(
      version: (json['version'] as num).toInt(),
      salt: const Base64Converter().fromJson(json['salt'] as String),
      parts: (json['parts'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
          int.parse(k),
          EncryptionResult.fromJson(e as Map<String, dynamic>),
        ),
      ),
    );

Map<String, dynamic> _$ArchiveMetadataToJson(ArchiveMetadata instance) =>
    <String, dynamic>{
      'version': instance.version,
      'salt': const Base64Converter().toJson(instance.salt),
      'parts': instance.parts.map((k, e) => MapEntry(k.toString(), e)),
    };
