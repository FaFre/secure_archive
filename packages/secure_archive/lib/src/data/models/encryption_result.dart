import 'package:json_annotation/json_annotation.dart';
import 'package:secure_archive/src/data/converters/base64_converter.dart';

part 'encryption_result.g.dart';

@JsonSerializable()
class EncryptionResult {
  @Base64Converter()
  final List<int> nonce;
  @Base64Converter()
  final List<int> mac;

  EncryptionResult({required this.nonce, required this.mac});

  factory EncryptionResult.fromJson(Map<String, dynamic> json) =>
      _$EncryptionResultFromJson(json);

  Map<String, dynamic> toJson() => _$EncryptionResultToJson(this);
}
