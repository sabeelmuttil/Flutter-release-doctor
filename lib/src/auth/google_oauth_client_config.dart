import 'dart:convert';
import 'dart:io';

import 'package:flutter_release_doctor/src/auth/bundled_google_oauth_client.dart';

enum GoogleOAuthClientType { installed, web, unknown }

/// Public OAuth client configuration (Desktop / installed). Never a service account.
class GoogleOAuthClientConfig {
  const GoogleOAuthClientConfig({
    required this.clientId,
    this.projectId,
    this.authUri = BundledGoogleOAuthClient.authUri,
    this.tokenUri = BundledGoogleOAuthClient.tokenUri,
    this.clientType = GoogleOAuthClientType.installed,
    this.clientSecret,
  });

  final String clientId;
  final String? projectId;
  final String authUri;
  final String tokenUri;
  final GoogleOAuthClientType clientType;

  /// Optional Desktop client secret. Treated as non-confidential for installed apps.
  /// Never a service-account private key.
  final String? clientSecret;

  bool get isServiceAccountShape => false;
}

class GoogleOAuthClientConfigException implements Exception {
  GoogleOAuthClientConfigException(this.message);
  final String message;

  @override
  String toString() => message;
}

/// Loads the bundled client, or an optional Desktop client JSON override.
///
/// Rejects Google service-account JSON (private keys) for the OAuth connect flow.
class GoogleOAuthClientConfigLoader {
  Future<GoogleOAuthClientConfig> load({String? oauthClientFile}) async {
    if (oauthClientFile == null || oauthClientFile.trim().isEmpty) {
      return BundledGoogleOAuthClient.config;
    }
    return loadFromFile(File(oauthClientFile.trim()));
  }

  Future<GoogleOAuthClientConfig> loadFromFile(File file) async {
    if (!await file.exists()) {
      throw GoogleOAuthClientConfigException(
        'OAuth client file not found: ${file.path}',
      );
    }
    final raw = await file.readAsString();
    return parseJson(raw, sourceLabel: file.path);
  }

  GoogleOAuthClientConfig parseJson(
    String raw, {
    String sourceLabel = 'oauth-client-file',
  }) {
    late final dynamic decoded;
    try {
      decoded = jsonDecode(raw);
    } catch (_) {
      throw GoogleOAuthClientConfigException(
        'OAuth client file is not valid JSON: $sourceLabel',
      );
    }
    if (decoded is! Map) {
      throw GoogleOAuthClientConfigException(
        'OAuth client file must be a JSON object: $sourceLabel',
      );
    }
    final map = decoded.map((k, v) => MapEntry(k.toString(), v));

    if (_looksLikeServiceAccount(map)) {
      throw GoogleOAuthClientConfigException(
        'Refusing service-account JSON for Google OAuth connect. '
        'Use a Desktop OAuth client configuration (public client ID), '
        'or run `flutter_release_doctor connect google` with the bundled client. '
        'Service-account private keys are not accepted for the normal login flow.',
      );
    }

    final installed = map['installed'] ?? map['web'];
    final root = installed is Map
        ? installed.map((k, v) => MapEntry(k.toString(), v))
        : map;

    if (_looksLikeServiceAccount(root)) {
      throw GoogleOAuthClientConfigException(
        'Refusing service-account JSON for Google OAuth connect. '
        'Desktop OAuth client files must not contain private_key.',
      );
    }

    final clientId = root['client_id']?.toString().trim();
    if (clientId == null || clientId.isEmpty) {
      throw GoogleOAuthClientConfigException(
        'OAuth client file is missing client_id: $sourceLabel',
      );
    }
    if (!clientId.contains('.apps.googleusercontent.com')) {
      throw GoogleOAuthClientConfigException(
        'OAuth client_id does not look like a Google OAuth client ID: $sourceLabel',
      );
    }

    final type = map.containsKey('installed')
        ? GoogleOAuthClientType.installed
        : map.containsKey('web')
            ? GoogleOAuthClientType.web
            : GoogleOAuthClientType.installed;

    final secret = root['client_secret']?.toString();
    if (secret != null &&
        (secret.contains('BEGIN PRIVATE KEY') ||
            secret.contains('PRIVATE KEY'))) {
      throw GoogleOAuthClientConfigException(
        'Refusing private-key material in OAuth client_secret.',
      );
    }

    return GoogleOAuthClientConfig(
      clientId: clientId,
      projectId: root['project_id']?.toString(),
      authUri: root['auth_uri']?.toString() ?? BundledGoogleOAuthClient.authUri,
      tokenUri:
          root['token_uri']?.toString() ?? BundledGoogleOAuthClient.tokenUri,
      clientType: type,
      clientSecret: (secret == null || secret.isEmpty) ? null : secret,
    );
  }

  bool _looksLikeServiceAccount(Map<Object?, Object?> map) {
    final type = map['type']?.toString().toLowerCase();
    if (type == 'service_account') return true;
    if (map.containsKey('private_key')) return true;
    if (map.containsKey('private_key_id') && map.containsKey('client_email')) {
      return true;
    }
    return false;
  }
}
