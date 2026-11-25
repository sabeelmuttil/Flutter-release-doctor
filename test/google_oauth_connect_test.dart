import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_release_doctor/flutter_release_doctor.dart';
import 'package:flutter_release_doctor/src/auth/auth_commands.dart';
import 'package:flutter_release_doctor/src/auth/browser_launcher.dart';
import 'package:flutter_release_doctor/src/auth/bundled_google_oauth_client.dart';
import 'package:flutter_release_doctor/src/auth/doctor_home.dart';
import 'package:flutter_release_doctor/src/auth/google_oauth_client_config.dart';
import 'package:flutter_release_doctor/src/auth/google_oauth_flow.dart';
import 'package:flutter_release_doctor/src/auth/google_token_store.dart';
import 'package:flutter_release_doctor/src/auth/oauth_pkce.dart';
import 'package:flutter_release_doctor/src/auth/secure_token_store.dart';
import 'package:flutter_release_doctor/src/live_store/google_play_live_check.dart';
import 'package:flutter_release_doctor/src/live_store/store_http.dart';
import 'package:test/test.dart';

class _MockHttp implements StoreHttpClient {
  _MockHttp(this.handler);

  final FutureOr<StoreHttpResponse> Function(
    String method,
    Uri uri, {
    Map<String, String>? headers,
    String? body,
  }) handler;

  @override
  Future<StoreHttpResponse> get(
    Uri uri, {
    Map<String, String>? headers,
  }) async {
    return handler('GET', uri, headers: headers);
  }

  @override
  Future<StoreHttpResponse> post(
    Uri uri, {
    Map<String, String>? headers,
    String? body,
  }) async {
    return handler('POST', uri, headers: headers, body: body);
  }
}

class _CaptureSink implements IOSink {
  final StringBuffer buffer = StringBuffer();

  @override
  Encoding encoding = utf8;

  String get text => buffer.toString();

  @override
  void add(List<int> data) => buffer.write(utf8.decode(data));

  @override
  void write(Object? object) => buffer.write(object);

  @override
  void writeAll(Iterable objects, [String separator = '']) =>
      buffer.writeAll(objects, separator);

  @override
  void writeln([Object? object = '']) => buffer.writeln(object);

  @override
  void writeCharCode(int charCode) => buffer.writeCharCode(charCode);

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future addStream(Stream<List<int>> stream) async {
    await for (final chunk in stream) {
      add(chunk);
    }
  }

  @override
  Future flush() async {}

  @override
  Future close() async {}

  @override
  Future get done => Future.value();
}

/// Test-only Desktop OAuth config (never a real Google credential).
GoogleOAuthClientConfig _testDesktopClient({
  String clientId =
      '111111111111-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com',
  String? clientSecret = 'TEST_ONLY_FAKE_CLIENT_SECRET',
}) {
  return GoogleOAuthClientConfig(
    clientId: clientId,
    projectId: 'flutter-release-doctor-test',
    clientType: GoogleOAuthClientType.installed,
    clientSecret: clientSecret,
  );
}

void main() {
  late Directory tempRoot;

  setUp(() async {
    tempRoot = await Directory.systemTemp.createTemp('frd_oauth_');
  });

  tearDown(() async {
    if (await tempRoot.exists()) {
      await tempRoot.delete(recursive: true);
    }
  });

  test('missing bundled configuration explains --oauth-client-file', () async {
    expect(BundledGoogleOAuthClient.clientId, isNull);
    expect(BundledGoogleOAuthClient.clientSecret, isNull);
    expect(BundledGoogleOAuthClient.config, isNull);
    expect(
      BundledGoogleOAuthClient.missingCredentialsHelp,
      contains('--oauth-client-file'),
    );
    expect(
      BundledGoogleOAuthClient.missingCredentialsHelp,
      contains('/secure/path/client_secret_xxx.json'),
    );

    final loader = GoogleOAuthClientConfigLoader(environment: {});
    await expectLater(
      loader.load(),
      throwsA(
        isA<GoogleOAuthClientConfigException>().having(
          (e) => e.message,
          'message',
          allOf(
            contains('--oauth-client-file'),
            contains('client_secret_xxx.json'),
            contains('outside the repository'),
          ),
        ),
      ),
    );

    final commands = AuthCommands(
      secureTokenStore: MemorySecureTokenStore(),
      doctorHome: DoctorHome(homePathOverride: '${tempRoot.path}/missing_home'),
      http: _MockHttp((_, __, {headers, body}) =>
          const StoreHttpResponse(statusCode: 500, body: '{}')),
      environment: const {},
    );
    final err = _CaptureSink();
    final code = await commands.connectGoogle(
      const ConnectGoogleOptions(noBrowser: true),
      stderrSink: err,
    );
    expect(code, 64);
    expect(err.text, contains('--oauth-client-file'));
    expect(err.text, isNot(contains('TEST_ONLY_FAKE_CLIENT_SECRET')));
  });

  test('oauth client loader rejects service-account JSON', () {
    final loader = GoogleOAuthClientConfigLoader(environment: {});
    expect(
      () => loader.parseJson(jsonEncode({
        'type': 'service_account',
        'private_key':
            '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----',
        'client_email': 'bot@example.iam.gserviceaccount.com',
      })),
      throwsA(
        isA<GoogleOAuthClientConfigException>().having(
          (e) => e.message,
          'message',
          contains('service-account'),
        ),
      ),
    );
  });

  test('connect google rejects service-account --oauth-client-file', () async {
    final saFile = File('${tempRoot.path}/service_account.json');
    await saFile.writeAsString(jsonEncode({
      'type': 'service_account',
      'private_key':
          '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----',
      'client_email': 'bot@example.iam.gserviceaccount.com',
    }));

    final commands = AuthCommands(
      secureTokenStore: MemorySecureTokenStore(),
      doctorHome: DoctorHome(homePathOverride: '${tempRoot.path}/sa_home'),
      http: _MockHttp((_, __, {headers, body}) =>
          const StoreHttpResponse(statusCode: 500, body: '{}')),
      environment: const {},
    );
    final err = _CaptureSink();
    final code = await commands.connectGoogle(
      ConnectGoogleOptions(
        noBrowser: true,
        oauthClientFile: saFile.path,
      ),
      stderrSink: err,
    );
    expect(code, 64);
    expect(err.text, contains('service-account'));
    expect(err.text, isNot(contains('BEGIN PRIVATE KEY')));
  });

  test('valid --oauth-client-file loads Desktop installed client', () async {
    final clientFile = File('${tempRoot.path}/desktop_client.json');
    await clientFile.writeAsString(jsonEncode({
      'installed': {
        'client_id':
            '999999999999-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com',
        'client_secret': 'TEST_ONLY_FAKE_CLIENT_SECRET',
        'project_id': 'enterprise-test',
        'auth_uri': 'https://accounts.google.com/o/oauth2/v2/auth',
        'token_uri': 'https://oauth2.googleapis.com/token',
      },
    }));

    final loader = GoogleOAuthClientConfigLoader(environment: {});
    final config = await loader.load(oauthClientFile: clientFile.path);
    expect(config.clientId, startsWith('999999999999-'));
    expect(config.projectId, 'enterprise-test');
    expect(config.clientSecret, 'TEST_ONLY_FAKE_CLIENT_SECRET');
    expect(config.clientType, GoogleOAuthClientType.installed);

    // Same path connect google uses for --oauth-client-file.
    final loadedAgain = await GoogleOAuthClientConfigLoader(environment: {})
        .load(oauthClientFile: clientFile.path);
    expect(loadedAgain.clientId, startsWith('999999999999-'));
    expect(loadedAgain.clientSecret, 'TEST_ONLY_FAKE_CLIENT_SECRET');
  });

  test('oauth client loader accepts Desktop installed client override', () {
    final loader = GoogleOAuthClientConfigLoader(environment: {});
    final config = loader.parseJson(jsonEncode({
      'installed': {
        'client_id':
            '999999999999-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com',
        'project_id': 'enterprise-test',
        'auth_uri': 'https://accounts.google.com/o/oauth2/v2/auth',
        'token_uri': 'https://oauth2.googleapis.com/token',
      },
    }));
    expect(config.clientId, startsWith('999999999999-'));
    expect(config.projectId, 'enterprise-test');
  });

  test('env GOOGLE_OAUTH_CLIENT_ID overrides missing bundled config', () async {
    final loader = GoogleOAuthClientConfigLoader(
      environment: {
        'GOOGLE_OAUTH_CLIENT_ID':
            '888888888888-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com',
        'GOOGLE_OAUTH_CLIENT_SECRET': 'TEST_ONLY_ENV_CLIENT_SECRET',
      },
    );
    final config = await loader.load();
    expect(config.clientId, startsWith('888888888888-'));
    expect(config.clientSecret, 'TEST_ONLY_ENV_CLIENT_SECRET');
  });

  test('first-run directory creation', () async {
    final homePath = '${tempRoot.path}/home/.flutter_release_doctor';
    final home = DoctorHome(homePathOverride: homePath);
    expect(await Directory(homePath).exists(), isFalse);

    final created = await home.ensureCreated();
    expect(created.path, homePath);
    expect(await Directory(homePath).exists(), isTrue);
    expect(await Directory('$homePath/cache').exists(), isTrue);
    expect(await Directory('$homePath/logs').exists(), isTrue);

    // Idempotent.
    await home.ensureCreated();
    expect(await Directory(homePath).exists(), isTrue);
  });

  test('secure token storage abstraction write/read/delete', () async {
    final store = MemorySecureTokenStore();
    final tokens = GoogleTokenStore(store);

    expect(await tokens.isSignedIn(), isFalse);
    await tokens.save(
      GoogleOAuthTokens(
        accessToken: 'access-abc',
        refreshToken: 'refresh-xyz',
        email: 'dev@example.com',
        expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
      ),
    );
    expect(await tokens.isSignedIn(), isTrue);

    final loaded = await tokens.read();
    expect(loaded?.accessToken, 'access-abc');
    expect(loaded?.refreshToken, 'refresh-xyz');
    expect(loaded?.email, 'dev@example.com');
    expect(loaded?.statusSummary, isNot(contains('access-abc')));
    expect(loaded?.statusSummary, contains('dev@example.com'));

    // Never lands in DoctorHome as a plain file.
    final homePath = '${tempRoot.path}/no_tokens';
    await DoctorHome(homePathOverride: homePath).ensureCreated();
    final files = await Directory(homePath)
        .list(recursive: true)
        .where((e) => e is File)
        .toList();
    for (final file in files) {
      final text = await File(file.path).readAsString();
      expect(text, isNot(contains('access-abc')));
      expect(text, isNot(contains('refresh-xyz')));
    }

    await tokens.clear();
    expect(await tokens.isSignedIn(), isFalse);
  });

  test('auth logout google clears secure tokens', () async {
    final store = MemorySecureTokenStore();
    final commands = AuthCommands(
      secureTokenStore: store,
      doctorHome: DoctorHome(homePathOverride: '${tempRoot.path}/logout_home'),
      http: _MockHttp((_, __, {headers, body}) =>
          const StoreHttpResponse(statusCode: 500, body: '{}')),
    );
    await commands.tokenStore.save(
      const GoogleOAuthTokens(accessToken: 'to-remove', refreshToken: 'r'),
    );
    expect(await commands.tokenStore.isSignedIn(), isTrue);

    final out = _CaptureSink();
    final code = await commands.authLogoutGoogle(stdoutSink: out);
    expect(code, 0);
    expect(out.text, contains('signed out'));
    expect(await commands.tokenStore.isSignedIn(), isFalse);
    expect(out.text, isNot(contains('to-remove')));
  });

  test('auth status without login', () async {
    final commands = AuthCommands(
      secureTokenStore: MemorySecureTokenStore(),
      doctorHome: DoctorHome(homePathOverride: '${tempRoot.path}/status_home'),
      http: _MockHttp((_, __, {headers, body}) =>
          const StoreHttpResponse(statusCode: 500, body: '{}')),
    );
    final out = _CaptureSink();
    final code = await commands.authStatus(stdoutSink: out);
    expect(code, 0);
    expect(out.text, contains('not signed in'));
    expect(out.text, contains('connect google'));
  });

  test('missing Play Console permission shows helpful error', () async {
    final http = _MockHttp((method, uri, {headers, body}) {
      if (uri.path.contains('/edits')) {
        return const StoreHttpResponse(
          statusCode: 403,
          body:
              '{"error":{"message":"The current user has insufficient permissions to perform the requested operation."}}',
        );
      }
      return const StoreHttpResponse(statusCode: 500, body: '{}');
    });

    final flow = GoogleOAuthFlow(
      clientConfig: _testDesktopClient(),
      tokenStore: GoogleTokenStore(MemorySecureTokenStore()),
      http: http,
      openBrowser: false,
      playPackageName: 'com.example.app',
    );

    await expectLater(
      flow.verifyPlayConsoleAccess('token'),
      throwsA(
        isA<PlayConsolePermissionException>().having(
          (e) => e.message,
          'message',
          allOf(
            contains('Play Console'),
            contains('com.example.app'),
            isNot(contains('ya29')),
          ),
        ),
      ),
    );
  });

  test('OAuth state mismatch is rejected', () async {
    final pkce = OauthPkce();
    final expected = pkce.generateState();
    expect(
      () => throw OauthStateMismatchException(
        expected: expected,
        actual: 'tampered-state',
      ),
      throwsA(isA<OauthStateMismatchException>()),
    );

    final store = MemorySecureTokenStore();
    final http = _MockHttp((method, uri, {headers, body}) {
      fail('Token exchange must not run after state mismatch');
    });

    late Uri authUrl;
    final flow = GoogleOAuthFlow(
      clientConfig: _testDesktopClient(),
      tokenStore: GoogleTokenStore(store),
      http: http,
      openBrowser: true,
      openUrl: (url) async {
        authUrl = url;
        final state = url.queryParameters['state']!;
        final redirect = Uri.parse(url.queryParameters['redirect_uri']!);
        // Fire a callback with a wrong state.
        unawaited(Future(() async {
          await Future<void>.delayed(const Duration(milliseconds: 20));
          final client = HttpClient();
          final request = await client.getUrl(
            redirect.replace(
              queryParameters: {
                'code': 'fake-code',
                'state': 'wrong-$state',
              },
            ),
          );
          final response = await request.close();
          await response.drain<void>();
          client.close(force: true);
        }));
      },
      callbackTimeout: const Duration(seconds: 5),
    );

    await expectLater(
      flow.connect(),
      throwsA(isA<OauthStateMismatchException>()),
    );
    expect(authUrl.queryParameters['code_challenge_method'], 'S256');
    expect(authUrl.queryParameters['code_challenge'], isNotEmpty);
    expect(authUrl.queryParameters['state'], isNotEmpty);
    expect(await GoogleTokenStore(store).isSignedIn(), isFalse);
  });

  test('PKCE challenge is S256 of verifier', () {
    final pkce = OauthPkce();
    final verifier = pkce.generateCodeVerifier();
    expect(verifier.length, greaterThanOrEqualTo(43));
    final challenge = pkce.codeChallengeS256(verifier);
    expect(challenge, isNot(contains('=')));
    expect(challenge, isNot(verifier));
  });

  test('offline mode works without login credentials', () async {
    final project = Directory('${tempRoot.path}/offline_app');
    await project.create(recursive: true);
    await File('${project.path}/pubspec.yaml').writeAsString('''
name: offline_app
version: 1.0.0+1
''');

    final report = await ReleaseDoctor().check(
      project,
      liveStore: LiveStoreOptions.offline,
      googleTokenStore: GoogleTokenStore(MemorySecureTokenStore()),
      environment: const {},
      storeHttp: _MockHttp((method, uri, {headers, body}) {
        fail('Offline mode must not call the network');
      }),
    );

    expect(
      report.findings.where((f) => f.source == FindingSource.liveApi),
      isEmpty,
    );
  });

  test('online mode without credentials is INFO not ERROR', () async {
    final findings = <Finding>[];
    await GooglePlayLiveCheck(
      http: _MockHttp((method, uri, {headers, body}) {
        fail('No network without credentials');
      }),
      environment: const {},
      packageName: 'com.example.app',
      googleTokenStore: GoogleTokenStore(MemorySecureTokenStore()),
    ).run(findings);

    final access = findings.where((f) => f.id == 'store-api-access');
    expect(access, isNotEmpty);
    expect(access.every((f) => f.level == FindingLevel.info), isTrue);
    expect(
      access.first.detail,
      contains('connect google'),
    );
    expect(DoctorReport(Directory.current, findings).score, 100);
  });

  test('CLI parses connect google and auth commands', () {
    final connect = parseConnectArguments([
      'connect',
      'google',
      '--no-browser',
      '--oauth-client-file',
      '/tmp/client.json',
      '--package',
      'com.example.app',
    ]);
    expect(connect.noBrowser, isTrue);
    expect(connect.oauthClientFile, '/tmp/client.json');
    expect(connect.packageName, 'com.example.app');

    expect(
      () => parseConnectArguments(['connect', 'apple']),
      throwsA(isA<CliUsageException>()),
    );
  });

  test('token exchange sends Desktop client credential with PKCE', () async {
    String? postedBody;
    final testClient = _testDesktopClient();
    final http = _MockHttp((method, uri, {headers, body}) {
      if (uri.path.contains('/token') || uri.host.contains('oauth2')) {
        postedBody = body;
        return StoreHttpResponse(
          statusCode: 200,
          body: jsonEncode({
            'access_token': 'ya29.mock-access',
            'refresh_token': '1//mock-refresh',
            'expires_in': 3600,
            'token_type': 'Bearer',
          }),
        );
      }
      if (uri.path.contains('userinfo')) {
        return const StoreHttpResponse(
          statusCode: 200,
          body: '{"email":"dev@example.com"}',
        );
      }
      return const StoreHttpResponse(statusCode: 404, body: '{}');
    });

    final store = MemorySecureTokenStore();
    final flow = GoogleOAuthFlow(
      clientConfig: testClient,
      tokenStore: GoogleTokenStore(store),
      http: http,
      openBrowser: true,
      openUrl: (url) async {
        final redirect = Uri.parse(url.queryParameters['redirect_uri']!);
        final state = url.queryParameters['state']!;
        unawaited(Future(() async {
          await Future<void>.delayed(const Duration(milliseconds: 20));
          final client = HttpClient();
          final request = await client.getUrl(
            redirect.replace(
              queryParameters: {'code': 'auth-code', 'state': state},
            ),
          );
          await (await request.close()).drain<void>();
          client.close(force: true);
        }));
      },
    );

    await flow.connect();
    expect(postedBody, contains('client_secret='));
    expect(
      postedBody,
      contains(Uri.encodeComponent(testClient.clientSecret!)),
    );
    expect(postedBody, contains('code_verifier='));
  });

  test('CLI connect google success path with mocked OAuth', () async {
    final store = MemorySecureTokenStore();
    final out = _CaptureSink();
    final err = _CaptureSink();
    final testClient = _testDesktopClient();

    late Uri capturedAuthUrl;
    final http = _MockHttp((method, uri, {headers, body}) {
      if (uri.host == 'oauth2.googleapis.com' || uri.path.contains('/token')) {
        return StoreHttpResponse(
          statusCode: 200,
          body: jsonEncode({
            'access_token': 'ya29.mock-access',
            'refresh_token': '1//mock-refresh',
            'expires_in': 3600,
            'token_type': 'Bearer',
            'scope': BundledGoogleOAuthClient.androidPublisherScope,
          }),
        );
      }
      if (uri.path.contains('userinfo')) {
        return const StoreHttpResponse(
          statusCode: 200,
          body: '{"email":"dev@example.com"}',
        );
      }
      return const StoreHttpResponse(statusCode: 404, body: '{}');
    });

    final commands = AuthCommands(
      secureTokenStore: store,
      doctorHome: DoctorHome(homePathOverride: '${tempRoot.path}/connect_home'),
      http: http,
      environment: const {},
    );

    // Drive GoogleOAuthFlow directly for determinism, then assert auth status.
    final flow = GoogleOAuthFlow(
      clientConfig: testClient,
      tokenStore: commands.tokenStore,
      http: http,
      openBrowser: true,
      openUrl: (url) async {
        capturedAuthUrl = url;
        final redirect = Uri.parse(url.queryParameters['redirect_uri']!);
        final state = url.queryParameters['state']!;
        unawaited(Future(() async {
          await Future<void>.delayed(const Duration(milliseconds: 20));
          final client = HttpClient();
          final request = await client.getUrl(
            redirect.replace(
              queryParameters: {'code': 'auth-code', 'state': state},
            ),
          );
          final response = await request.close();
          final html = await response.transform(utf8.decoder).join();
          expect(html, contains('Connected to Google'));
          client.close(force: true);
        }));
      },
    );

    final result = await flow.connect();
    expect(result.tokens.email, 'dev@example.com');
    expect(result.tokens.accessToken, 'ya29.mock-access');
    expect(capturedAuthUrl.queryParameters['code_challenge_method'], 'S256');
    expect(await commands.tokenStore.isSignedIn(), isTrue);

    final statusOut = _CaptureSink();
    expect(await commands.authStatus(stdoutSink: statusOut), 0);
    expect(statusOut.text, contains('dev@example.com'));
    expect(statusOut.text, isNot(contains('ya29.mock-access')));
    expect(statusOut.text, isNot(contains('1//mock-refresh')));
    expect(statusOut.text, isNot(contains('TEST_ONLY_FAKE_CLIENT_SECRET')));

    // Ensure connect CLI wiring accepts flags.
    final code = await runFlutterReleaseDoctor(
      ['auth', 'status'],
      stdoutSink: out,
      stderrSink: err,
      authCommands: commands,
    );
    expect(code, 0);
  });

  test('connect google with --oauth-client-file never prints secrets',
      () async {
    final clientFile = File('${tempRoot.path}/print_safe_client.json');
    await clientFile.writeAsString(jsonEncode({
      'installed': {
        'client_id':
            '777777777777-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com',
        'client_secret': 'TEST_ONLY_MUST_NOT_PRINT',
        'project_id': 'print-safe-test',
      },
    }));

    final store = MemorySecureTokenStore();
    final out = _CaptureSink();
    final err = _CaptureSink();
    final http = _MockHttp((method, uri, {headers, body}) {
      if (uri.host == 'oauth2.googleapis.com' || uri.path.contains('/token')) {
        return StoreHttpResponse(
          statusCode: 200,
          body: jsonEncode({
            'access_token': 'ya29.mock-access',
            'refresh_token': '1//mock-refresh',
            'expires_in': 3600,
            'token_type': 'Bearer',
          }),
        );
      }
      if (uri.path.contains('userinfo')) {
        return const StoreHttpResponse(
          statusCode: 200,
          body: '{"email":"dev@example.com"}',
        );
      }
      return const StoreHttpResponse(statusCode: 404, body: '{}');
    });

    final browser = BrowserLauncher(
      runProcess: (executable, arguments) async {
        // AuthCommands uses the real browser launcher; simulate opening the
        // authorization URL by completing the loopback callback.
        final authUrl = Uri.parse(arguments.last);
        final redirect = Uri.parse(authUrl.queryParameters['redirect_uri']!);
        final state = authUrl.queryParameters['state']!;
        unawaited(Future(() async {
          await Future<void>.delayed(const Duration(milliseconds: 20));
          final client = HttpClient();
          final request = await client.getUrl(
            redirect.replace(
              queryParameters: {'code': 'auth-code', 'state': state},
            ),
          );
          await (await request.close()).drain<void>();
          client.close(force: true);
        }));
        return ProcessResult(0, 0, '', '');
      },
    );

    final commands = AuthCommands(
      secureTokenStore: store,
      doctorHome: DoctorHome(homePathOverride: '${tempRoot.path}/print_home'),
      http: http,
      browserLauncher: browser,
      environment: const {},
    );

    final code = await commands.connectGoogle(
      ConnectGoogleOptions(oauthClientFile: clientFile.path),
      stdoutSink: out,
      stderrSink: err,
    );

    expect(code, 0);
    expect(out.text, contains('Client ID:'));
    expect(out.text, contains('777777777777-'));
    expect(out.text, contains('Using Desktop OAuth client file:'));
    expect(out.text, isNot(contains('TEST_ONLY_MUST_NOT_PRINT')));
    expect(err.text, isNot(contains('TEST_ONLY_MUST_NOT_PRINT')));
    expect(out.text, isNot(contains('ya29.mock-access')));
    expect(out.text, isNot(contains('1//mock-refresh')));
    expect(err.text, isNot(contains('ya29.mock-access')));
  });
}
