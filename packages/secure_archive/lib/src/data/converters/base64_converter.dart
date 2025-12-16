import 'dart:convert';

import 'package:json_annotation/json_annotation.dart';

class Base64Converter extends JsonConverter<List<int>, String> {
  const Base64Converter();

  @override
  List<int> fromJson(String json) {
    return base64Decode(json);
  }

  @override
  String toJson(List<int> object) {
    return base64Encode(object);
  }
}
