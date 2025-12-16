import 'dart:io';

import 'package:path/path.dart' as p;

String? validateRequired(String? value, {String name = 'Value'}) {
  if (value == null || value.isEmpty) {
    return '$name is required';
  }

  return null;
}

String? validatePath(String? value) {
  if (value == null || value.isEmpty) {
    return 'Path cannot be empty';
  }

  // Check for invalid characters
  // ignore: unnecessary_raw_strings
  final invalidChars = RegExp(r'[<>"|?*]');
  if (invalidChars.hasMatch(value)) {
    return 'Path contains invalid characters';
  }

  // Validate path structure
  try {
    p.normalize(value);
  } catch (e) {
    return 'Invalid path format';
  }

  return null;
}

String? validateDirectoryExisting(String? value) {
  if (value == null || value.isEmpty) {
    return 'Path cannot be empty';
  }

  if (!Directory(value).existsSync()) {
    return 'Directory is not existing';
  }

  return null;
}

String? validateDirectoryNotExisting(String? value) {
  if (value == null || value.isEmpty) {
    return 'Path cannot be empty';
  }

  if (Directory(value).existsSync()) {
    return 'Directory already exisits';
  }

  return null;
}

String? validateFileNotExisting(String? value) {
  if (value == null || value.isEmpty) {
    return 'Path cannot be empty';
  }

  if (File(value).existsSync()) {
    return 'File already exisits';
  }

  return null;
}

String? validateFileExisting(String? value) {
  if (value == null || value.isEmpty) {
    return 'Path cannot be empty';
  }

  if (!File(value).existsSync()) {
    return 'File not existing';
  }

  return null;
}
