// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'encryption_result.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

EncryptionResult _$EncryptionResultFromJson(Map<String, dynamic> json) =>
    EncryptionResult(
      nonce: const Base64Converter().fromJson(json['nonce'] as String),
      mac: const Base64Converter().fromJson(json['mac'] as String),
    );

Map<String, dynamic> _$EncryptionResultToJson(EncryptionResult instance) =>
    <String, dynamic>{
      'nonce': const Base64Converter().toJson(instance.nonce),
      'mac': const Base64Converter().toJson(instance.mac),
    };
