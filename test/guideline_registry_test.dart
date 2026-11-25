import 'dart:io';

import 'package:flutter_release_doctor/flutter_release_doctor.dart';
import 'package:flutter_release_doctor/src/live_store/store_http.dart';
import 'package:test/test.dart';

class _ThrowingHttp implements StoreHttpClient {
  @override
  Future<StoreHttpResponse> get(Uri uri, {Map<String, String>? headers}) {
    throw StateError('Offline guideline scans must not call the network');
  }

  @override
  Future<StoreHttpResponse> post(
    Uri uri, {
    Map<String, String>? headers,
    String? body,
  }) {
    throw StateError('Offline guideline scans must not call the network');
  }
}

void main() {
  late Directory tempRoot;

  setUp(() async {
    tempRoot = await Directory.systemTemp.createTemp('guideline_registry_');
  });

  tearDown(() async {
    if (await tempRoot.exists()) {
      await tempRoot.delete(recursive: true);
    }
  });

  test('registry exposes versioned Google and Apple rules', () {
    expect(GuidelineRuleRegistry.guidelineVersion, '2026.1');
    expect(GuidelineRuleRegistry.all, isNotEmpty);
    expect(
      GuidelineRuleRegistry.all.map((r) => r.id),
      containsAll([
        'play-data-safety-review',
        'play-privacy-policy-missing',
        'play-account-deletion-missing',
        'play-sensitive-permissions-review',
        'play-families-audience-unknown',
        'play-insecure-networking-risk',
        'play-signing-release-readiness',
        'play-reviewer-access-missing',
        'apple-privacy-policy-missing',
        'apple-account-deletion-missing',
        'apple-iap-missing',
        'apple-sign-in-with-apple-review',
        'apple-privacy-manifest-review',
        'apple-permission-purpose-strings',
        'apple-reviewer-access-missing',
        'apple-universal-links-entitlements',
        'apple-att-review',
      ]),
    );
    for (final rule in GuidelineRuleRegistry.all) {
      expect(rule.ruleVersion, GuidelineRuleRegistry.guidelineVersion);
      expect(rule.guidelineReference, isNotEmpty);
    }
  });

  test('reports include guidelineVersion and MANUAL REVIEW section', () async {
    final project = await _baseProject(tempRoot, 'report_fields');
    await File('${project.path}/android/app/src/main/AndroidManifest.xml')
        .writeAsString('''
<manifest>
  <uses-permission android:name="android.permission.CAMERA" />
</manifest>
''');

    final report = await ReleaseDoctor().check(
      project,
      storeHttp: _ThrowingHttp(),
      environment: const {},
    );

    expect(report.toJson()['guidelineVersion'], DoctorReport.guidelineVersion);
    expect(report.toMarkdown(), contains('Guideline version'));
    expect(report.toMarkdown(), contains('## MANUAL REVIEW'));
    expect(report.toConsole(), contains('Guideline version:'));
    expect(
      report.findings.any((f) => f.level == FindingLevel.manualReview),
      isTrue,
    );
    expect(report.disclaimer, contains('risk scanner'));
    expect(
      report.disclaimer.toLowerCase(),
      contains('not a store approval certificate'),
    );
  });

  test('Google privacy + permissions findings include required fields',
      () async {
    final project = await _baseProject(tempRoot, 'google_fields');
    await File('${project.path}/android/app/src/main/AndroidManifest.xml')
        .writeAsString('''
<manifest>
  <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
</manifest>
''');

    final report = await ReleaseDoctor().check(project);
    final privacy = report.findings.singleWhere(
      (f) => f.id == 'play-privacy-policy-missing',
    );
    expect(privacy.platform, GuidelinePlatform.googlePlay);
    expect(privacy.guidelineReference, isNotEmpty);
    expect(privacy.ruleVersion, DoctorReport.guidelineVersion);
    expect(privacy.evidence, isNotEmpty);
    expect(privacy.file, contains('AndroidManifest.xml'));
    expect(privacy.fix, isNotNull);
    expect(privacy.detail.toLowerCase(), contains('potential rejection risk'));

    final perms = report.findings.singleWhere(
      (f) => f.id == 'play-sensitive-permissions-review',
    );
    expect(perms.level, FindingLevel.manualReview);
    expect(perms.platform, GuidelinePlatform.googlePlay);
  });

  test('Apple privacy manifest and empty purpose string rules', () async {
    final project = await _baseProject(tempRoot, 'apple_privacy');
    await Directory('${project.path}/ios/Runner').create(recursive: true);
    await File('${project.path}/ios/Runner/Info.plist').writeAsString('''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>com.example.app</string>
  <key>NSCameraUsageDescription</key>
  <string></string>
  <key>NSLocationWhenInUseUsageDescription</key>
  <string>TODO</string>
</dict>
</plist>
''');

    final report = await ReleaseDoctor().check(project);
    final purpose = report.findings.singleWhere(
      (f) => f.id == 'apple-permission-purpose-strings',
    );
    expect(purpose.level, FindingLevel.warning);
    expect(purpose.platform, GuidelinePlatform.appStore);
    expect(purpose.guidelineReference, contains('5.1.1'));

    final manifest = report.findings.singleWhere(
      (f) => f.id == 'apple-privacy-manifest-review',
    );
    expect(manifest.level, FindingLevel.warning);
    expect(manifest.detail.toLowerCase(), contains('potential rejection risk'));
  });

  test('false positive: localhost HTTP does not trigger Play networking rule',
      () async {
    final project = await _baseProject(tempRoot, 'http_false_positive');
    await Directory('${project.path}/lib').create(recursive: true);
    await File('${project.path}/lib/main.dart').writeAsString('''
void main() {
  const url = 'http://localhost:8080/api';
}
''');

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.any((f) => f.id == 'play-insecure-networking-risk'),
      isFalse,
    );
  });

  test('profile downgrades Universal Links when disabled', () async {
    final project = await _baseProject(
      tempRoot,
      'universal_links_profile',
      storeYaml: '''
store_profile:
  uses_universal_links: false
''',
    );
    await Directory('${project.path}/ios/Runner').create(recursive: true);
    await File('${project.path}/ios/Runner/Runner.entitlements')
        .writeAsString('''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.developer.associated-domains</key>
  <array></array>
</dict>
</plist>
''');

    final report = await ReleaseDoctor().check(project);
    final links = report.findings.where(
      (f) => f.id == 'apple-universal-links-entitlements',
    );
    for (final f in links) {
      expect(f.level, isNot(FindingLevel.warning));
    }
  });

  test('offline mode makes no network calls for guideline scan', () async {
    final project = await _baseProject(tempRoot, 'offline_no_network');
    await File('${project.path}/android/app/src/main/AndroidManifest.xml')
        .writeAsString('''
<manifest>
  <uses-permission android:name="android.permission.CAMERA" />
</manifest>
''');

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
    expect(
      report.findings.any((f) => f.id == 'play-privacy-policy-missing'),
      isTrue,
    );
  });

  test('high-risk security findings remain non-suppressible', () {
    expect(nonSuppressibleFindingIds, contains('hard-coded-secret'));
    expect(nonSuppressibleFindingIds, contains('insecure-http'));
    expect(nonSuppressibleFindingIds, contains('android-release-signing'));
    expect(
        nonSuppressibleFindingIds, contains('play-insecure-networking-risk'));
  });
}

Future<Directory> _baseProject(
  Directory root,
  String name, {
  String? storeYaml,
}) async {
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
  buildTypes {
    release {
    }
  }
}
''');
  await File('${project.path}/android/app/src/main/AndroidManifest.xml')
      .writeAsString('<manifest package="com.example.app"></manifest>');
  if (storeYaml != null) {
    await File('${project.path}/.release-doctor.yaml').writeAsString('''
version: 1
$storeYaml
''');
  }
  return project;
}
