import 'dart:io';

/// Helpers for safe file:line evidence in findings.
class Evidence {
  /// Returns a repo-relative POSIX-style path.
  static String relativePath(Directory project, File file) {
    final prefix = project.path;
    if (file.path.startsWith(prefix)) {
      return file.path
          .substring(prefix.length)
          .replaceFirst(RegExp(r'^[/\\]'), '')
          .replaceAll('\\', '/');
    }
    return file.uri.pathSegments.last;
  }

  /// 1-based line number of [index] within [text].
  static int lineOfOffset(String text, int index) {
    if (index <= 0) return 1;
    var line = 1;
    final end = index < text.length ? index : text.length;
    for (var i = 0; i < end; i++) {
      if (text.codeUnitAt(i) == 0x0A) line++;
    }
    return line;
  }

  static String classifySecretMatch(String matched) {
    final lower = matched.toLowerCase();
    if (lower.contains('password') || lower.contains('passwd')) {
      return 'password-like assignment';
    }
    if (lower.contains('api') && lower.contains('key')) {
      return 'api-key-like assignment';
    }
    if (lower.contains('token')) return 'token-like assignment';
    if (lower.contains('secret')) return 'secret-like assignment';
    if (lower.contains('private')) return 'private-key-like material';
    return 'credential-like assignment';
  }
}
