import 'dart:convert';

import 'package:flutter_release_doctor/src/auth/secure_token_store.dart';

/// Stored Google OAuth tokens (held only in [SecureTokenStore]).
class GoogleOAuthTokens {
  const GoogleOAuthTokens({
    required this.accessToken,
    this.refreshToken,
    this.expiresAt,
    this.tokenType = 'Bearer',
    this.scope,
    this.email,
  });

  final String accessToken;
  final String? refreshToken;
  final DateTime? expiresAt;
  final String tokenType;
  final String? scope;
  final String? email;

  bool get isExpired {
    if (expiresAt == null) return false;
    return DateTime.now().isAfter(
      expiresAt!.subtract(const Duration(minutes: 2)),
    );
  }

  bool get hasRefreshToken =>
      refreshToken != null && refreshToken!.trim().isNotEmpty;

  Map<String, dynamic> toJson() => {
        'access_token': accessToken,
        'refresh_token': refreshToken,
        'expires_at': expiresAt?.toUtc().toIso8601String(),
        'token_type': tokenType,
        'scope': scope,
        'email': email,
      };

  factory GoogleOAuthTokens.fromJson(Map<String, dynamic> json) {
    DateTime? expiresAt;
    final expiryRaw = json['expires_at'] ?? json['expiry'];
    if (expiryRaw != null) {
      expiresAt = DateTime.tryParse(expiryRaw.toString())?.toUtc();
    } else if (json['expires_in'] != null) {
      final seconds = int.tryParse(json['expires_in'].toString());
      if (seconds != null) {
        expiresAt = DateTime.now().toUtc().add(Duration(seconds: seconds));
      }
    }
    return GoogleOAuthTokens(
      accessToken: json['access_token']?.toString() ?? '',
      refreshToken: json['refresh_token']?.toString(),
      expiresAt: expiresAt,
      tokenType: json['token_type']?.toString() ?? 'Bearer',
      scope: json['scope']?.toString(),
      email: json['email']?.toString(),
    );
  }

  GoogleOAuthTokens copyWith({
    String? accessToken,
    String? refreshToken,
    DateTime? expiresAt,
    String? tokenType,
    String? scope,
    String? email,
  }) {
    return GoogleOAuthTokens(
      accessToken: accessToken ?? this.accessToken,
      refreshToken: refreshToken ?? this.refreshToken,
      expiresAt: expiresAt ?? this.expiresAt,
      tokenType: tokenType ?? this.tokenType,
      scope: scope ?? this.scope,
      email: email ?? this.email,
    );
  }

  /// Safe status summary — never includes token values.
  String get statusSummary {
    final parts = <String>['Google OAuth: signed in'];
    if (email != null && email!.isNotEmpty) {
      parts.add('account=$email');
    }
    if (expiresAt != null) {
      parts.add('access_token_expires=${expiresAt!.toUtc().toIso8601String()}');
    }
    parts.add(
        hasRefreshToken ? 'refresh_token=present' : 'refresh_token=absent');
    return parts.join(', ');
  }
}

/// Persists Google OAuth tokens exclusively via [SecureTokenStore].
class GoogleTokenStore {
  GoogleTokenStore(this.secureStore);

  final SecureTokenStore secureStore;

  static const storageKey = 'google.oauth.tokens';

  Future<void> save(GoogleOAuthTokens tokens) async {
    if (tokens.accessToken.isEmpty) {
      throw ArgumentError('accessToken must not be empty');
    }
    await secureStore.write(storageKey, jsonEncode(tokens.toJson()));
  }

  Future<GoogleOAuthTokens?> read() async {
    final raw = await secureStore.read(storageKey);
    if (raw == null || raw.trim().isEmpty) return null;
    try {
      final decoded = jsonDecode(raw);
      if (decoded is! Map) return null;
      final tokens = GoogleOAuthTokens.fromJson(
        decoded.map((k, v) => MapEntry(k.toString(), v)),
      );
      if (tokens.accessToken.isEmpty) return null;
      return tokens;
    } catch (_) {
      return null;
    }
  }

  Future<void> clear() async {
    await secureStore.delete(storageKey);
  }

  Future<bool> isSignedIn() async {
    final tokens = await read();
    return tokens != null;
  }
}
