import 'dart:io';

import 'package:flutter_release_doctor/flutter_release_doctor.dart';
import 'package:flutter_release_doctor/src/live_store/app_store_live_check.dart';
import 'package:flutter_release_doctor/src/live_store/google_play_live_check.dart';
import 'package:flutter_release_doctor/src/live_store/live_store_verification.dart';
import 'package:flutter_release_doctor/src/live_store/store_http.dart';
import 'package:test/test.dart';

class _RecordingHttp implements StoreHttpClient {
  final List<Uri> gets = [];
  final List<Uri> posts = [];
  StoreHttpResponse Function(Uri uri, {Map<String, String>? headers})? onGet;
  StoreHttpResponse Function(
    Uri uri, {
    Map<String, String>? headers,
    String? body,
  })? onPost;

  @override
  Future<StoreHttpResponse> get(
    Uri uri, {
    Map<String, String>? headers,
  }) async {
    gets.add(uri);
    final handler = onGet;
    if (handler == null) {
      throw StateError('Unexpected GET $uri');
    }
    return handler(uri, headers: headers);
  }

  @override
  Future<StoreHttpResponse> post(
    Uri uri, {
    Map<String, String>? headers,
    String? body,
  }) async {
    posts.add(uri);
    final handler = onPost;
    if (handler == null) {
      throw StateError('Unexpected POST $uri');
    }
    return handler(uri, headers: headers, body: body);
  }
}

class _ThrowingHttp implements StoreHttpClient {
  @override
  Future<StoreHttpResponse> get(
    Uri uri, {
    Map<String, String>? headers,
  }) {
    throw StateError('Network must not be called in offline mode');
  }

  @override
  Future<StoreHttpResponse> post(
    Uri uri, {
    Map<String, String>? headers,
    String? body,
  }) {
    throw StateError('Network must not be called in offline mode');
  }
}

void main() {
  late Directory tempRoot;

  setUp(() async {
    tempRoot = await Directory.systemTemp.createTemp('live_store_');
  });

  tearDown(() async {
    if (await tempRoot.exists()) {
      await tempRoot.delete(recursive: true);
    }
  });

  test('offline mode makes no network calls', () async {
    final project = await _baseProject(tempRoot, 'offline');
    final report = await ReleaseDoctor().check(
      project,
      liveStore: LiveStoreOptions.offline,
      storeHttp: _ThrowingHttp(),
      environment: const {},
    );
    expect(
      report.findings.where((f) => f.source == FindingSource.liveApi),
      isEmpty,
    );
    expect(report.hasLiveApiFindings, isFalse);
    expect(
      report.disclaimer,
      isNot(contains(LiveStoreVerification.disclaimer)),
    );
  });

  test('--no-store-check skips live checks even with online', () async {
    final findings = <Finding>[];
    await LiveStoreVerification(
      options: const LiveStoreOptions(
        online: true,
        enabled: false,
      ),
      http: _ThrowingHttp(),
      environment: const {},
    ).run(Directory.current, DoctorConfig.empty, findings);
    expect(findings, isEmpty);
  });

  test('missing Google credentials emit INFO without score impact', () async {
    final findings = <Finding>[];
    await GooglePlayLiveCheck(
      http: _ThrowingHttp(),
      environment: const {},
      packageName: 'com.example.app',
    ).run(findings);

    final access = findings.where((f) => f.id == 'store-api-access').toList();
    expect(access, isNotEmpty);
    expect(access.every((f) => f.level == FindingLevel.info), isTrue);
    expect(access.every((f) => f.source == FindingSource.liveApi), isTrue);

    final report = DoctorReport(Directory.current, findings);
    expect(report.score, 100);
  });

  test('missing Apple credentials emit INFO without score impact', () async {
    final findings = <Finding>[];
    await AppStoreLiveCheck(
      http: _ThrowingHttp(),
      environment: const {},
      bundleId: 'com.example.app',
    ).run(findings);

    final access =
        findings.where((f) => f.id == 'app-store-connect-access').toList();
    expect(access, isNotEmpty);
    expect(access.every((f) => f.level == FindingLevel.info), isTrue);
    expect(access.every((f) => f.source == FindingSource.liveApi), isTrue);

    final report = DoctorReport(Directory.current, findings);
    expect(report.score, 100);
  });

  test('mocked Google Play success reports access and tracks', () async {
    final http = _RecordingHttp();
    http.onPost = (uri, {headers, body}) {
      expect(uri.path, contains('/applications/com.example.app/edits'));
      return const StoreHttpResponse(
        statusCode: 200,
        body: '{"id":"edit-1"}',
      );
    };
    http.onGet = (uri, {headers}) {
      expect(uri.path, contains('/tracks'));
      return const StoreHttpResponse(
        statusCode: 200,
        body: '''
{
  "tracks": [
    {
      "track": "production",
      "releases": [
        {"status": "completed", "versionCodes": ["42"]}
      ]
    }
  ]
}
''',
      );
    };

    final findings = <Finding>[];
    await GooglePlayLiveCheck(
      http: http,
      environment: const {'GOOGLE_PLAY_ACCESS_TOKEN': 'test-token'},
      packageName: 'com.example.app',
    ).run(findings);

    expect(
      findings.any(
        (f) => f.id == 'store-api-access' && f.level == FindingLevel.passed,
      ),
      isTrue,
    );
    expect(
      findings.any(
        (f) =>
            f.id == 'google-play-release-status' &&
            f.detail.contains('production') &&
            f.detail.contains('42'),
      ),
      isTrue,
    );
    expect(
      findings.any((f) => f.id == 'google-play-vitals-summary'),
      isTrue,
    );
    expect(http.posts, hasLength(1));
    expect(http.gets, hasLength(1));
  });

  test('mocked Google Play auth failure emits WARNING without secrets',
      () async {
    final http = _RecordingHttp();
    http.onPost = (uri, {headers, body}) {
      return const StoreHttpResponse(
        statusCode: 401,
        body:
            '{"error":"invalid_grant","access_token":"ya29.SECRET_TOKEN_VALUE"}',
      );
    };

    final findings = <Finding>[];
    await GooglePlayLiveCheck(
      http: http,
      environment: const {'GOOGLE_PLAY_ACCESS_TOKEN': 'test-token'},
      packageName: 'com.example.app',
    ).run(findings);

    final warning = findings.firstWhere(
      (f) => f.id == 'store-api-access' && f.level == FindingLevel.warning,
    );
    expect(warning.detail, isNot(contains('ya29.SECRET_TOKEN_VALUE')));
    expect(warning.detail, contains('[REDACTED]'));
    expect(warning.source, FindingSource.liveApi);
  });

  test('mocked App Store Connect success reports access and TestFlight',
      () async {
    final http = _RecordingHttp();
    http.onGet = (uri, {headers}) {
      if (uri.path.endsWith('/apps')) {
        return const StoreHttpResponse(
          statusCode: 200,
          body: '{"data":[{"id":"app-123","type":"apps"}]}',
        );
      }
      if (uri.path.endsWith('/builds')) {
        return const StoreHttpResponse(
          statusCode: 200,
          body: '''
{
  "data": [
    {
      "id": "build-1",
      "attributes": {
        "version": "99",
        "processingState": "VALID",
        "uploadedDate": "2026-03-01T12:00:00Z"
      }
    }
  ]
}
''',
        );
      }
      throw StateError('Unexpected GET ${uri.path}');
    };

    final findings = <Finding>[];
    await AppStoreLiveCheck(
      http: http,
      environment: const {
        'APP_STORE_CONNECT_ACCESS_TOKEN': 'asc-test-token',
      },
      bundleId: 'com.example.app',
    ).run(findings);

    expect(
      findings.any(
        (f) =>
            f.id == 'app-store-connect-access' &&
            f.level == FindingLevel.passed,
      ),
      isTrue,
    );
    expect(
      findings.any(
        (f) =>
            f.id == 'testflight-build-status' &&
            f.detail.contains('processingState=VALID') &&
            f.detail.contains('version=99'),
      ),
      isTrue,
    );
    expect(http.gets, hasLength(2));
  });

  test('mocked App Store Connect auth failure emits WARNING without JWT',
      () async {
    const jwt =
        'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFiYzEyMyJ9.eyJpc3MiOiJpc3N1ZXIifQ.signature';
    final http = _RecordingHttp();
    http.onGet = (uri, {headers}) {
      return StoreHttpResponse(
        statusCode: 401,
        body: 'Unauthorized Bearer $jwt access denied',
      );
    };

    final findings = <Finding>[];
    await AppStoreLiveCheck(
      http: http,
      environment: const {
        'APP_STORE_CONNECT_ACCESS_TOKEN': 'asc-test-token',
      },
      bundleId: 'com.example.app',
    ).run(findings);

    final warning = findings.firstWhere(
      (f) =>
          f.id == 'app-store-connect-access' && f.level == FindingLevel.warning,
    );
    expect(warning.detail, isNot(contains(jwt)));
    expect(warning.detail, contains('[REDACTED'));
  });

  test('secret redaction strips tokens, JWTs, and private keys', () {
    const raw = '''
Bearer ya29.a0AfH6SMCx_SECRET
eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg
-----END PRIVATE KEY-----
"private_key":"-----BEGIN PRIVATE KEY-----abc-----END PRIVATE KEY-----"
"access_token":"secret-access-token-value"
''';
    final redacted = redactStoreApiError(raw);
    expect(redacted, isNot(contains('ya29.a0AfH6SMCx_SECRET')));
    expect(redacted, isNot(contains('secret-access-token-value')));
    expect(redacted, contains('[REDACTED'));
    expect(redacted, isNot(contains('BEGIN PRIVATE KEY-----abc')));
  });

  test('CLI parses --online --store and --no-store-check', () {
    final onlineBoth = parseCliArguments([
      'check',
      '.',
      '--online',
      '--store',
      'both',
    ]);
    expect(onlineBoth.liveStore.online, isTrue);
    expect(onlineBoth.liveStore.store, StoreTarget.both);
    expect(onlineBoth.liveStore.shouldRun, isTrue);

    final googleOnly = parseCliArguments([
      'check',
      '--online',
      '--store=google',
    ]);
    expect(googleOnly.liveStore.includeGoogle, isTrue);
    expect(googleOnly.liveStore.includeApple, isFalse);

    final appleOnly = parseCliArguments([
      'check',
      '--online',
      '--store',
      'apple',
    ]);
    expect(appleOnly.liveStore.includeGoogle, isFalse);
    expect(appleOnly.liveStore.includeApple, isTrue);

    final skipped = parseCliArguments([
      'check',
      '--online',
      '--no-store-check',
    ]);
    expect(skipped.liveStore.online, isTrue);
    expect(skipped.liveStore.enabled, isFalse);
    expect(skipped.liveStore.shouldRun, isFalse);

    final offlineDefault = parseCliArguments(['check', '.']);
    expect(offlineDefault.liveStore.online, isFalse);
    expect(offlineDefault.liveStore.shouldRun, isFalse);
  });

  test('CLI rejects invalid --store values', () {
    expect(
      () => parseCliArguments(['check', '--store', 'amazon']),
      throwsA(
        isA<CliUsageException>().having(
          (e) => e.message,
          'message',
          contains('google|apple|both'),
        ),
      ),
    );
    expect(
      () => parseCliArguments(['check', '--store']),
      throwsA(isA<CliUsageException>()),
    );
  });

  test('store_integrations config is loaded from YAML', () async {
    final project = await _baseProject(tempRoot, 'config_store');
    await File('${project.path}/.release-doctor.yaml').writeAsString('''
version: 1
store_integrations:
  google_play:
    package_name: com.config.google
  app_store:
    bundle_id: com.config.apple
''');
    final result = await DoctorConfigLoader().load(project);
    expect(result.findings, isEmpty);
    expect(
      result.config.storeIntegrations.googlePlayPackageName,
      'com.config.google',
    );
    expect(
      result.config.storeIntegrations.appStoreBundleId,
      'com.config.apple',
    );
  });

  test('ReleaseDoctor online path uses config package and mock HTTP', () async {
    final project = await _baseProject(tempRoot, 'online_wire');
    await File('${project.path}/.release-doctor.yaml').writeAsString('''
version: 1
store_integrations:
  google_play:
    package_name: com.wire.google
  app_store:
    bundle_id: com.wire.apple
''');

    final http = _RecordingHttp();
    http.onPost = (uri, {headers, body}) {
      expect(uri.path, contains('com.wire.google'));
      return const StoreHttpResponse(
          statusCode: 403, body: '{"error":"denied"}');
    };
    http.onGet = (uri, {headers}) {
      expect(uri.queryParameters['filter[bundleId]'], 'com.wire.apple');
      return const StoreHttpResponse(
          statusCode: 403, body: '{"error":"denied"}');
    };

    final report = await ReleaseDoctor().check(
      project,
      liveStore: const LiveStoreOptions(online: true, store: StoreTarget.both),
      storeHttp: http,
      environment: const {
        'GOOGLE_PLAY_ACCESS_TOKEN': 'g-token',
        'APP_STORE_CONNECT_ACCESS_TOKEN': 'a-token',
      },
    );

    expect(report.hasLiveApiFindings, isTrue);
    expect(report.disclaimer, contains(LiveStoreVerification.disclaimer));
    expect(
      report.findings.any((f) => f.id == 'store-api-access'),
      isTrue,
    );
    expect(
      report.findings.any((f) => f.id == 'app-store-connect-access'),
      isTrue,
    );
    expect(http.posts, isNotEmpty);
    expect(http.gets, isNotEmpty);
  });
}

Future<Directory> _baseProject(Directory root, String name) async {
  final project = Directory('${root.path}/$name');
  await project.create(recursive: true);
  await File('${project.path}/pubspec.yaml').writeAsString('''
name: sample_app
version: 1.0.0+1
''');
  await Directory('${project.path}/android/app/src/main')
      .create(recursive: true);
  await File('${project.path}/android/app/build.gradle').writeAsString('''
android {
  defaultConfig {
    applicationId "com.example.app"
  }
}
''');
  await File('${project.path}/android/app/src/main/AndroidManifest.xml')
      .writeAsString('''
<manifest package="com.example.app"></manifest>
''');
  await Directory('${project.path}/ios/Runner').create(recursive: true);
  await File('${project.path}/ios/Runner/Info.plist').writeAsString('''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>com.example.app</string>
</dict>
</plist>
''');
  return project;
}
