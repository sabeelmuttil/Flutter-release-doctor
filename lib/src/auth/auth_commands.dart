import 'dart:io';

import 'package:flutter_release_doctor/src/auth/browser_launcher.dart';
import 'package:flutter_release_doctor/src/auth/bundled_google_oauth_client.dart';
import 'package:flutter_release_doctor/src/auth/doctor_home.dart';
import 'package:flutter_release_doctor/src/auth/google_oauth_client_config.dart';
import 'package:flutter_release_doctor/src/auth/google_oauth_flow.dart';
import 'package:flutter_release_doctor/src/auth/google_token_store.dart';
import 'package:flutter_release_doctor/src/auth/oauth_pkce.dart';
import 'package:flutter_release_doctor/src/auth/secure_token_store.dart';
import 'package:flutter_release_doctor/src/doctor_config.dart';
import 'package:flutter_release_doctor/src/live_store/store_http.dart';

class ConnectGoogleOptions {
  const ConnectGoogleOptions({
    this.noBrowser = false,
    this.oauthClientFile,
    this.packageName,
  });

  final bool noBrowser;
  final String? oauthClientFile;
  final String? packageName;
}

/// CLI handlers for `connect` and `auth` commands.
class AuthCommands {
  AuthCommands({
    SecureTokenStore? secureTokenStore,
    DoctorHome? doctorHome,
    StoreHttpClient? http,
    BrowserLauncher? browserLauncher,
    GoogleOAuthClientConfigLoader? clientConfigLoader,
    Directory? workingDirectory,
    Map<String, String>? environment,
  })  : secureTokenStore = secureTokenStore ?? PlatformSecureTokenStore(),
        doctorHome = doctorHome ?? DoctorHome(),
        http = http ?? DartIoStoreHttpClient(),
        browserLauncher = browserLauncher ?? BrowserLauncher(),
        clientConfigLoader = clientConfigLoader ??
            GoogleOAuthClientConfigLoader(environment: environment),
        workingDirectory = workingDirectory ?? Directory.current;

  final SecureTokenStore secureTokenStore;
  final DoctorHome doctorHome;
  final StoreHttpClient http;
  final BrowserLauncher browserLauncher;
  final GoogleOAuthClientConfigLoader clientConfigLoader;
  final Directory workingDirectory;

  GoogleTokenStore get tokenStore => GoogleTokenStore(secureTokenStore);

  Future<int> connectGoogle(
    ConnectGoogleOptions options, {
    IOSink? stdoutSink,
    IOSink? stderrSink,
  }) async {
    final out = stdoutSink ?? stdout;
    final err = stderrSink ?? stderr;

    try {
      final home = await doctorHome.ensureCreated();
      out.writeln('Using local directory: ${home.path}');
      out.writeln(
        'Tokens will be stored in OS secure storage '
        '(Keychain / Credential Manager / Secret Service), not in this folder.',
      );

      final clientConfig = await clientConfigLoader.load(
        oauthClientFile: options.oauthClientFile,
      );
      if (options.oauthClientFile != null &&
          options.oauthClientFile!.trim().isNotEmpty) {
        out.writeln(
          'Using Desktop OAuth client file: ${options.oauthClientFile}',
        );
      } else {
        out.writeln(
          'Using Google Desktop OAuth client from environment / local override '
          '(no credentials are embedded in the repository).',
        );
      }
      // Client ID is public; never print client_secret or tokens.
      out.writeln('Client ID: ${clientConfig.clientId}');

      final packageName = options.packageName?.trim().isNotEmpty == true
          ? options.packageName!.trim()
          : await _resolvePackageName();

      if (options.noBrowser) {
        out.writeln(
          'Browser launch disabled (--no-browser). '
          'Open the authorization URL printed below.',
        );
      } else {
        out.writeln('Opening your browser for Google sign-in…');
      }

      final flow = GoogleOAuthFlow(
        clientConfig: clientConfig,
        tokenStore: tokenStore,
        http: http,
        browserLauncher: browserLauncher,
        openBrowser: true,
        openUrl: options.noBrowser
            ? (url) async {
                out.writeln('');
                out.writeln('Open this URL in your browser to authorize:');
                out.writeln(url.toString());
                out.writeln('');
                out.writeln('Waiting for authorization callback on localhost…');
              }
            : null,
        playPackageName: packageName,
      );

      final result = await flow.connect();
      final tokens = result.tokens;

      out.writeln('');
      out.writeln('Success: Google account connected.');
      if (tokens.email != null && tokens.email!.isNotEmpty) {
        out.writeln('Account: ${tokens.email}');
      }
      out.writeln(
        'Refresh/access tokens were saved to OS secure storage. '
        'They are never written to your Flutter project or reports.',
      );
      out.writeln('');
      out.writeln('Next:');
      out.writeln(
        '  flutter_release_doctor check . --online --store google',
      );
      return 0;
    } on PlayConsolePermissionException catch (e) {
      err.writeln(e.message);
      return 1;
    } on OauthStateMismatchException catch (e) {
      err.writeln(e.toString());
      return 1;
    } on GoogleOAuthClientConfigException catch (e) {
      err.writeln(e.message);
      return 64;
    } on GoogleOAuthFlowException catch (e) {
      err.writeln(e.message);
      return 1;
    } catch (e) {
      err.writeln('Google connect failed: $e');
      return 1;
    }
  }

  Future<int> authStatus({
    IOSink? stdoutSink,
    IOSink? stderrSink,
  }) async {
    final out = stdoutSink ?? stdout;
    await doctorHome.ensureCreated();
    final tokens = await tokenStore.read();
    if (tokens == null) {
      out.writeln('Google: not signed in');
      out.writeln('Run: flutter_release_doctor connect google');
      out.writeln('Apple: not configured via OAuth connect (use env secrets)');
      return 0;
    }
    out.writeln(tokens.statusSummary);
    out.writeln(
      'Token values are stored in OS secure storage and are not printed.',
    );
    return 0;
  }

  Future<int> authLogoutGoogle({
    IOSink? stdoutSink,
    IOSink? stderrSink,
  }) async {
    final out = stdoutSink ?? stdout;
    await doctorHome.ensureCreated();
    await tokenStore.clear();
    out.writeln('Google: signed out. Secure tokens removed.');
    return 0;
  }

  Future<String?> _resolvePackageName() async {
    try {
      final configResult = await DoctorConfigLoader().load(workingDirectory);
      final configured =
          configResult.config.storeIntegrations.googlePlayPackageName;
      if (configured != null && configured.trim().isNotEmpty) {
        return configured.trim();
      }
    } catch (_) {}

    final groovy = File(
      '${workingDirectory.path}${Platform.pathSeparator}android'
      '${Platform.pathSeparator}app${Platform.pathSeparator}build.gradle',
    );
    final kts = File('${groovy.path}.kts');
    for (final file in [groovy, kts]) {
      if (!await file.exists()) continue;
      final text = await file.readAsString();
      final match = RegExp(
        r'''applicationId\s*(?:=|:)\s*["']([^"']+)["']''',
      ).firstMatch(text);
      if (match != null) return match.group(1);
    }
    return null;
  }
}

/// Resolves a usable Google access token from env or secure OAuth store.
class GoogleAccessTokenResolver {
  GoogleAccessTokenResolver({
    required this.http,
    required this.environment,
    GoogleTokenStore? tokenStore,
    GoogleOAuthClientConfig? clientConfig,
  })  : tokenStore = tokenStore ?? GoogleTokenStore(PlatformSecureTokenStore()),
        clientConfig = clientConfig;

  final StoreHttpClient http;
  final Map<String, String> environment;
  final GoogleTokenStore tokenStore;
  final GoogleOAuthClientConfig? clientConfig;

  Future<String?> resolve() async {
    final envToken = environment['GOOGLE_PLAY_ACCESS_TOKEN']?.trim();
    if (envToken != null && envToken.isNotEmpty) {
      return envToken;
    }

    final stored = await tokenStore.read();
    if (stored == null) return null;

    var config = clientConfig ?? BundledGoogleOAuthClient.config;
    if (config == null) {
      try {
        config = await GoogleOAuthClientConfigLoader(environment: environment)
            .load();
      } on GoogleOAuthClientConfigException {
        config = null;
      }
    }

    if (config != null) {
      final flow = GoogleOAuthFlow(
        clientConfig: config,
        tokenStore: tokenStore,
        http: http,
        openBrowser: false,
      );
      final refreshed = await flow.refreshIfNeeded(stored);
      final token = refreshed?.accessToken ?? stored.accessToken;
      if (token.isNotEmpty) return token;
      return null;
    }

    // No OAuth client available to refresh — return non-expired stored token.
    if (!stored.isExpired && stored.accessToken.isNotEmpty) {
      return stored.accessToken;
    }
    return null;
  }

  bool get hasServiceAccountEnv {
    final path = environment['GOOGLE_PLAY_SERVICE_ACCOUNT_FILE']?.trim() ??
        environment['GOOGLE_APPLICATION_CREDENTIALS']?.trim();
    return path != null && path.isNotEmpty;
  }
}
