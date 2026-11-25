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

  /// Optional Desktop client secret for token exchange.
  /// Never a service-account private key. Never print this value.
  final String? clientSecret;

  bool get isServiceAccountShape => false;
}

class GoogleOAuthClientConfigException implements Exception {
  GoogleOAuthClientConfigException(this.message);
  final String message;

  @override
  String toString() => message;
}

/// Loads Desktop OAuth client config from file, env, or optional bundled values.
///
/// Rejects Google service-account JSON (private keys) for the OAuth connect flow.
class GoogleOAuthClientConfigLoader {
  GoogleOAuthClientConfigLoader({Map<String, String>? environment})
      : _environmentOverride = environment;

  /// When non-null (including empty), used instead of [Platform.environment].
  /// Pass `{}` in tests to ignore the host process environment.
  final Map<String, String>? _environmentOverride;

  Map<String, String> get _env => _environmentOverride ?? Platform.environment;

  /// Resolve order:
  /// 1. `--oauth-client-file`
  /// 2. `FLUTTER_RELEASE_DOCTOR_GOOGLE_OAUTH_CLIENT_FILE`
  /// 3. `GOOGLE_OAUTH_CLIENT_ID` (+ optional `GOOGLE_OAUTH_CLIENT_SECRET`)
  /// 4. Optional bundled config (normally unset in this repo)
  Future<GoogleOAuthClientConfig> load({String? oauthClientFile}) async {
    final fileArg = oauthClientFile?.trim();
    if (fileArg != null && fileArg.isNotEmpty) {
      return loadFromFile(File(fileArg));
    }

    final envFile =
        _env['FLUTTER_RELEASE_DOCTOR_GOOGLE_OAUTH_CLIENT_FILE']?.trim();
    if (envFile != null && envFile.isNotEmpty) {
      return loadFromFile(File(envFile));
    }

    final envClientId = _env['GOOGLE_OAUTH_CLIENT_ID']?.trim();
    if (envClientId != null && envClientId.isNotEmpty) {
      if (!envClientId.contains('.apps.googleusercontent.com')) {
        throw GoogleOAuthClientConfigException(
          'GOOGLE_OAUTH_CLIENT_ID does not look like a Google OAuth client ID.',
        );
      }
      final envSecret = _env['GOOGLE_OAUTH_CLIENT_SECRET']?.trim();
      return GoogleOAuthClientConfig(
        clientId: envClientId,
        clientSecret:
            (envSecret == null || envSecret.isEmpty) ? null : envSecret,
        clientType: GoogleOAuthClientType.installed,
      );
    }

    final bundled = BundledGoogleOAuthClient.config;
    if (bundled != null) return bundled;

    throw GoogleOAuthClientConfigException(
      BundledGoogleOAuthClient.missingCredentialsHelp,
    );
  }

  Future<GoogleOAuthClientConfig> loadFromFile(File file) async {
    if (!await file.exists()) {
      throw GoogleOAuthClientConfigException(
        'OAuth client file not found: ${file.path}\n\n'
        '${BundledGoogleOAuthClient.missingCredentialsHelp}',
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
        'Use a Desktop OAuth client JSON with --oauth-client-file '
        '(never a service-account private key).',
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
