import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_release_doctor/src/auth/browser_launcher.dart';
import 'package:flutter_release_doctor/src/auth/bundled_google_oauth_client.dart';
import 'package:flutter_release_doctor/src/auth/google_oauth_client_config.dart';
import 'package:flutter_release_doctor/src/auth/google_token_store.dart';
import 'package:flutter_release_doctor/src/auth/oauth_pkce.dart';
import 'package:flutter_release_doctor/src/live_store/store_http.dart';

class PlayConsolePermissionException implements Exception {
  PlayConsolePermissionException(this.message);
  final String message;

  @override
  String toString() => message;
}

class GoogleOAuthFlowException implements Exception {
  GoogleOAuthFlowException(this.message);
  final String message;

  @override
  String toString() => message;
}

class GoogleOAuthConnectResult {
  const GoogleOAuthConnectResult({
    required this.tokens,
    required this.authorizationUrl,
  });

  final GoogleOAuthTokens tokens;
  final Uri authorizationUrl;
}

/// Desktop Google OAuth (loopback + PKCE + state) for Play Developer API access.
class GoogleOAuthFlow {
  GoogleOAuthFlow({
    required this.clientConfig,
    required this.tokenStore,
    required this.http,
    BrowserLauncher? browserLauncher,
    Future<void> Function(Uri url)? openUrl,
    OauthPkce? pkce,
    this.openBrowser = true,
    this.playPackageName,
    Duration? callbackTimeout,
    Future<HttpServer> Function(InternetAddress address, int port)? bindServer,
  })  : browserLauncher = browserLauncher ?? BrowserLauncher(),
        openUrl = openUrl,
        pkce = pkce ?? OauthPkce(),
        callbackTimeout = callbackTimeout ?? const Duration(minutes: 5),
        _bindServer = bindServer ?? HttpServer.bind;

  final GoogleOAuthClientConfig clientConfig;
  final GoogleTokenStore tokenStore;
  final StoreHttpClient http;
  final BrowserLauncher browserLauncher;
  final Future<void> Function(Uri url)? openUrl;
  final OauthPkce pkce;
  final bool openBrowser;
  final String? playPackageName;
  final Duration callbackTimeout;
  final Future<HttpServer> Function(InternetAddress address, int port)
      _bindServer;

  static const successHtml = '''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>Flutter Release Doctor</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 40rem; margin: 4rem auto; padding: 0 1rem; color: #122; }
    h1 { font-size: 1.4rem; }
    p { line-height: 1.5; }
  </style>
</head>
<body>
  <h1>Connected to Google</h1>
  <p>Flutter Release Doctor authorized successfully. You can close this tab and return to the terminal.</p>
  <p>Live Play checks: <code>flutter_release_doctor check . --online --store google</code></p>
</body>
</html>
''';

  Future<GoogleOAuthConnectResult> connect() async {
    final server = await _bindServer(InternetAddress.loopbackIPv4, 0);
    final redirectUri =
        Uri.parse('http://127.0.0.1:${server.port}/oauth2callback');
    final codeVerifier = pkce.generateCodeVerifier();
    final codeChallenge = pkce.codeChallengeS256(codeVerifier);
    final state = pkce.generateState();

    final authUrl = _authorizationUrl(
      redirectUri: redirectUri,
      codeChallenge: codeChallenge,
      state: state,
    );

    final completer = Completer<Map<String, String>>();
    late StreamSubscription<HttpRequest> subscription;
    subscription = server.listen((request) async {
      try {
        if (request.uri.path != '/oauth2callback') {
          request.response.statusCode = HttpStatus.notFound;
          await request.response.close();
          return;
        }
        final params = request.uri.queryParameters;
        request.response.statusCode = HttpStatus.ok;
        request.response.headers.contentType = ContentType.html;
        if (params['error'] != null) {
          request.response.write(_errorHtml(params['error']!));
        } else {
          request.response.write(successHtml);
        }
        await request.response.close();
        if (!completer.isCompleted) {
          completer.complete(Map<String, String>.from(params));
        }
      } catch (e) {
        if (!completer.isCompleted) {
          completer.completeError(e);
        }
      }
    });

    try {
      if (openBrowser) {
        final opener = openUrl ?? browserLauncher.open;
        await opener(authUrl);
      }

      final params = await completer.future.timeout(
        callbackTimeout,
        onTimeout: () => throw GoogleOAuthFlowException(
          'Timed out waiting for Google authorization. '
          'Re-run `flutter_release_doctor connect google` and complete sign-in in the browser.',
        ),
      );

      if (params['error'] != null) {
        throw GoogleOAuthFlowException(
          'Google authorization failed: ${params['error']}'
          '${params['error_description'] != null ? ' (${params['error_description']})' : ''}.',
        );
      }

      final returnedState = params['state'];
      if (returnedState == null || returnedState != state) {
        throw OauthStateMismatchException(
          expected: state,
          actual: returnedState,
        );
      }

      final code = params['code'];
      if (code == null || code.isEmpty) {
        throw GoogleOAuthFlowException(
          'Google authorization response did not include a code.',
        );
      }

      final tokens = await _exchangeCode(
        code: code,
        codeVerifier: codeVerifier,
        redirectUri: redirectUri,
      );

      await verifyPlayConsoleAccess(tokens.accessToken);

      final withEmail = await _attachEmail(tokens);
      await tokenStore.save(withEmail);

      return GoogleOAuthConnectResult(
        tokens: withEmail,
        authorizationUrl: authUrl,
      );
    } finally {
      await subscription.cancel();
      await server.close(force: true);
    }
  }

  Uri _authorizationUrl({
    required Uri redirectUri,
    required String codeChallenge,
    required String state,
  }) {
    return Uri.parse(clientConfig.authUri).replace(
      queryParameters: {
        'client_id': clientConfig.clientId,
        'redirect_uri': redirectUri.toString(),
        'response_type': 'code',
        'scope': BundledGoogleOAuthClient.scopes.join(' '),
        'state': state,
        'code_challenge': codeChallenge,
        'code_challenge_method': 'S256',
        'access_type': 'offline',
        'prompt': 'consent',
      },
    );
  }

  Future<GoogleOAuthTokens> _exchangeCode({
    required String code,
    required String codeVerifier,
    required Uri redirectUri,
  }) async {
    final body = StringBuffer()
      ..write('code=${Uri.encodeComponent(code)}')
      ..write('&client_id=${Uri.encodeComponent(clientConfig.clientId)}')
      ..write('&redirect_uri=${Uri.encodeComponent(redirectUri.toString())}')
      ..write('&grant_type=authorization_code')
      ..write('&code_verifier=${Uri.encodeComponent(codeVerifier)}');
    if (clientConfig.clientSecret != null &&
        clientConfig.clientSecret!.isNotEmpty) {
      body.write(
        '&client_secret=${Uri.encodeComponent(clientConfig.clientSecret!)}',
      );
    }

    final response = await http.post(
      Uri.parse(clientConfig.tokenUri),
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: body.toString(),
    );

    if (response.statusCode < 200 || response.statusCode >= 300) {
      final detail = redactStoreApiError(response.body);
      final hint = detail.toLowerCase().contains('client_secret')
          ? ' Google Desktop OAuth typically requires the installed-app '
              'client_secret on token exchange (even with PKCE). '
              'Pass a Desktop client JSON via --oauth-client-file, or set '
              'GOOGLE_OAUTH_CLIENT_ID / GOOGLE_OAUTH_CLIENT_SECRET '
              '(keep credentials outside the repository).'
          : '';
      throw GoogleOAuthFlowException(
        'Token exchange failed (HTTP ${response.statusCode}). $detail$hint',
      );
    }

    final json = response.jsonBody;
    if (json == null) {
      throw GoogleOAuthFlowException('Token endpoint returned invalid JSON.');
    }
    final tokens = GoogleOAuthTokens.fromJson(json);
    if (tokens.accessToken.isEmpty) {
      throw GoogleOAuthFlowException(
        'Token endpoint response did not include an access_token.',
      );
    }
    return tokens;
  }

  Future<GoogleOAuthTokens> _attachEmail(GoogleOAuthTokens tokens) async {
    try {
      final response = await http.get(
        Uri.parse(BundledGoogleOAuthClient.userInfoUri),
        headers: {'Authorization': 'Bearer ${tokens.accessToken}'},
      );
      if (response.statusCode >= 200 && response.statusCode < 300) {
        final email = response.jsonBody?['email']?.toString();
        if (email != null && email.isNotEmpty) {
          return tokens.copyWith(email: email);
        }
      }
    } catch (_) {}
    return tokens;
  }

  /// Probes Play Developer API when a package name is known.
  Future<void> verifyPlayConsoleAccess(String accessToken) async {
    final pkg = playPackageName?.trim();
    if (pkg == null || pkg.isEmpty) return;

    final response = await http.post(
      Uri.parse(
        'https://androidpublisher.googleapis.com/androidpublisher/v3/'
        'applications/${Uri.encodeComponent(pkg)}/edits',
      ),
      headers: {
        'Authorization': 'Bearer $accessToken',
        'Content-Type': 'application/json',
      },
      body: '{}',
    );

    if (response.statusCode == 401 || response.statusCode == 403) {
      if (_isInsufficientPlayPermission(response.body) ||
          response.statusCode == 403) {
        throw PlayConsolePermissionException(
          'Your Google account signed in successfully, but it does not appear '
          'to have Google Play Console API access for `$pkg`.\n\n'
          'Fix:\n'
          '  1. Open https://play.google.com/console\n'
          '  2. Ensure this Google account is a user on the Play Console developer account\n'
          '  3. Confirm the app `$pkg` exists and you can view it\n'
          '  4. Re-run: flutter_release_doctor connect google\n\n'
          'Details: ${redactStoreApiError(response.body)}',
        );
      }
    }
  }

  bool _isInsufficientPlayPermission(String body) {
    final lower = body.toLowerCase();
    return lower.contains('insufficient') ||
        lower.contains('permission') ||
        lower.contains('forbidden') ||
        lower.contains('accessdenied') ||
        lower.contains('access_denied');
  }

  String _errorHtml(String error) => '''
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><title>Authorization failed</title></head>
<body>
  <h1>Authorization failed</h1>
  <p>${const HtmlEscape().convert(error)}</p>
  <p>Return to the terminal and try again.</p>
</body></html>
''';

  /// Refreshes an access token using the stored refresh token.
  Future<GoogleOAuthTokens?> refreshIfNeeded(GoogleOAuthTokens tokens) async {
    if (!tokens.isExpired) return tokens;
    if (!tokens.hasRefreshToken) return tokens;

    final body = StringBuffer()
      ..write('client_id=${Uri.encodeComponent(clientConfig.clientId)}')
      ..write('&grant_type=refresh_token')
      ..write(
        '&refresh_token=${Uri.encodeComponent(tokens.refreshToken!)}',
      );
    if (clientConfig.clientSecret != null &&
        clientConfig.clientSecret!.isNotEmpty) {
      body.write(
        '&client_secret=${Uri.encodeComponent(clientConfig.clientSecret!)}',
      );
    }

    final response = await http.post(
      Uri.parse(clientConfig.tokenUri),
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: body.toString(),
    );
    if (response.statusCode < 200 || response.statusCode >= 300) {
      return null;
    }
    final json = response.jsonBody;
    if (json == null) return null;
    final refreshed = GoogleOAuthTokens.fromJson(json).copyWith(
      refreshToken: json['refresh_token']?.toString() ?? tokens.refreshToken,
      email: tokens.email,
    );
    if (refreshed.accessToken.isEmpty) return null;
    await tokenStore.save(refreshed);
    return refreshed;
  }
}
