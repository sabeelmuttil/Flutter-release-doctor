import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

/// PKCE helpers (S256) and OAuth `state` generation.
class OauthPkce {
  OauthPkce({Random? random}) : _random = random ?? Random.secure();

  final Random _random;

  static const _unreserved =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

  /// RFC 7636 code_verifier (43–128 chars).
  String generateCodeVerifier({int length = 64}) {
    final bounded = length.clamp(43, 128);
    final buffer = StringBuffer();
    for (var i = 0; i < bounded; i++) {
      buffer.write(_unreserved[_random.nextInt(_unreserved.length)]);
    }
    return buffer.toString();
  }

  /// BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) without padding.
  String codeChallengeS256(String codeVerifier) {
    final digest = sha256.convert(utf8.encode(codeVerifier));
    return base64UrlEncodeNoPad(Uint8List.fromList(digest.bytes));
  }

  String generateState({int length = 32}) {
    final bytes = List<int>.generate(length, (_) => _random.nextInt(256));
    return base64UrlEncodeNoPad(Uint8List.fromList(bytes));
  }

  static String base64UrlEncodeNoPad(List<int> bytes) {
    return base64Url.encode(bytes).replaceAll('=', '');
  }
}

class OauthStateMismatchException implements Exception {
  OauthStateMismatchException({
    required this.expected,
    required this.actual,
  });

  final String expected;
  final String? actual;

  @override
  String toString() =>
      'OAuth state mismatch: the authorization response did not match the '
      'request (possible CSRF). Expected a matching state parameter.';
}
