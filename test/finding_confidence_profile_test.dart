import 'dart:io';

import 'package:flutter_release_doctor/flutter_release_doctor.dart';
import 'package:test/test.dart';

void main() {
  late Directory tempRoot;

  setUp(() async {
    tempRoot =
        await Directory.systemTemp.createTemp('release_doctor_confidence_');
  });

  tearDown(() async {
    if (await tempRoot.exists()) {
      await tempRoot.delete(recursive: true);
    }
  });

  test('manual-review findings do not reduce score', () async {
    final project = await _baseProject(
      tempRoot,
      'manual_score',
      pubspecExtra: '''
dependencies:
  firebase_analytics: ^11.0.0
''',
    );

    final report = await ReleaseDoctor().check(project);
    final manual = report.findings.where(
      (f) => f.level == FindingLevel.manualReview,
    );
    expect(manual, isNotEmpty);
    final scoreFromManual = manual.fold<int>(
      0,
      (sum, f) => sum + (f.affectsScore ? 1 : 0),
    );
    expect(scoreFromManual, 0);

    // Baseline score without counting manual reviews: compare that manual
    // findings alone would not subtract if they were the only soft signals.
    final withoutManual = DoctorReport(
      project,
      report.findings
          .where((f) => f.level != FindingLevel.manualReview)
          .toList(),
    );
    expect(report.score, withoutManual.score);
  });

  test('physical_goods profile suppresses Play Billing / Apple IAP risks',
      () async {
    final project = await _baseProject(
      tempRoot,
      'physical_profile',
      transactionType: 'digital_goods',
      yamlExtra: '''
store_profile:
  business_model: physical_goods
''',
      pubspecExtra: '''
dependencies:
  razorpay_flutter: ^1.3.0
''',
    );

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where((f) => f.id == 'play-billing-bypass-risk'),
      isEmpty,
    );
    expect(
      report.findings.where((f) => f.id == 'apple-iap-missing'),
      isEmpty,
    );
    expect(
      report.findings
          .any((f) => f.id == 'play-physical-goods-payments-allowed'),
      isTrue,
    );
  });

  test('email_password profile does not WARN about Sign in with Apple',
      () async {
    final project = await _baseProject(
      tempRoot,
      'email_auth_profile',
      yamlExtra: '''
store_profile:
  authentication: email_password
''',
      pubspecExtra: '''
dependencies:
  google_sign_in: ^6.0.0
''',
    );

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where(
        (f) =>
            f.id == 'apple-sign-in-with-apple-review' &&
            f.level == FindingLevel.warning,
      ),
      isEmpty,
    );
  });

  test('uses_location=true downgrades location permission to manual review',
      () async {
    final project = await _baseProject(
      tempRoot,
      'location_profile',
      yamlExtra: '''
store_profile:
  uses_location: true
''',
    );
    await _writeAndroidManifest(project, '''
<manifest>
  <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
</manifest>
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.id == 'android-sensitive-permissions',
    );
    expect(finding.level, FindingLevel.manualReview);
    expect(finding.confidence, FindingConfidence.low);
    expect(finding.affectsScore, isFalse);
  });

  test('uses_universal_links=false avoids associated-domain WARNING', () async {
    final project = await _baseProject(
      tempRoot,
      'no_universal_links',
      yamlExtra: '''
store_profile:
  uses_universal_links: false
''',
    );
    final runner = Directory(
      '${project.path}${Platform.pathSeparator}ios'
      '${Platform.pathSeparator}Runner',
    );
    await runner.create(recursive: true);
    await File('${runner.path}${Platform.pathSeparator}Info.plist')
        .writeAsString('''
<plist><dict>
  <key>FlutterDeepLinkingEnabled</key>
  <true/>
  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleURLSchemes</key>
      <array><string>myapp</string></array>
    </dict>
  </array>
</dict></plist>
''');
    await File('${runner.path}${Platform.pathSeparator}Runner.entitlements')
        .writeAsString('''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.developer.associated-domains</key>
  <array>
    <string>webcredentials:example.com</string>
  </array>
</dict>
</plist>
''');

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where(
        (f) =>
            f.id == 'ios-associated-domains' && f.level == FindingLevel.warning,
      ),
      isEmpty,
    );
    // webcredentials / URL schemes alone must not create associated-domain noise.
    expect(
      report.findings.where((f) => f.id == 'ios-associated-domains'),
      isEmpty,
    );
  });

  test(
      'uses_universal_links=false with concrete applinks is MANUAL REVIEW only',
      () async {
    final project = await _baseProject(
      tempRoot,
      'ul_false_with_applinks',
      yamlExtra: '''
store_profile:
  uses_universal_links: false
''',
    );
    final runner = Directory(
      '${project.path}${Platform.pathSeparator}ios'
      '${Platform.pathSeparator}Runner',
    );
    await runner.create(recursive: true);
    await File('${runner.path}${Platform.pathSeparator}Runner.entitlements')
        .writeAsString('''
<plist><dict>
  <key>com.apple.developer.associated-domains</key>
  <array>
    <string>applinks:example.com</string>
  </array>
</dict></plist>
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.id == 'ios-associated-domains',
    );
    expect(finding.level, FindingLevel.manualReview);
    expect(finding.detail, contains('uses_universal_links=false'));
    expect(finding.affectsScore, isFalse);
  });

  test('uses_android_app_links=false downgrades missing host to INFO',
      () async {
    final project = await _baseProject(
      tempRoot,
      'no_android_app_links',
      yamlExtra: '''
store_profile:
  uses_android_app_links: false
''',
    );
    await _writeAndroidManifest(project, '''
<manifest>
  <application>
    <activity android:name=".MainActivity">
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.BROWSABLE" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:scheme="https" />
      </intent-filter>
    </activity>
  </application>
</manifest>
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.id == 'android-app-links-host',
    );
    expect(finding.level, FindingLevel.info);
    expect(finding.confidence, FindingConfidence.low);
  });

  test('HTTPS App Links missing host remains WARNING when profile unknown',
      () async {
    final project = await _baseProject(tempRoot, 'android_app_links_warn');
    await _writeAndroidManifest(project, '''
<manifest>
  <application>
    <activity android:name=".MainActivity">
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.BROWSABLE" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:scheme="https" />
      </intent-filter>
    </activity>
  </application>
</manifest>
''');

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings
          .singleWhere((f) => f.id == 'android-app-links-host')
          .level,
      FindingLevel.warning,
    );
  });

  test('payment SDK unresolved URL schemes are MANUAL REVIEW not WARNING',
      () async {
    final project = await _baseProject(tempRoot, 'sdk_url_scheme');
    final runner = Directory(
      '${project.path}${Platform.pathSeparator}ios'
      '${Platform.pathSeparator}Runner',
    );
    await runner.create(recursive: true);
    await File('${runner.path}${Platform.pathSeparator}Info.plist')
        .writeAsString(r'''
<plist><dict>
  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleURLSchemes</key>
      <array>
        <string>$(REVERSED_CLIENT_ID)</string>
      </array>
    </dict>
  </array>
</dict></plist>
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.id == 'ios-custom-url-scheme',
    );
    expect(finding.level, FindingLevel.manualReview);
    expect(finding.confidence, FindingConfidence.low);
    expect(finding.evidenceSummary, contains('Google Sign-In'));
  });

  test('empty app-owned custom URL scheme remains WARNING', () async {
    final project = await _baseProject(tempRoot, 'empty_url_scheme');
    final runner = Directory(
      '${project.path}${Platform.pathSeparator}ios'
      '${Platform.pathSeparator}Runner',
    );
    await runner.create(recursive: true);
    await File('${runner.path}${Platform.pathSeparator}Info.plist')
        .writeAsString('''
<plist><dict>
  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleURLSchemes</key>
      <array>
        <string></string>
      </array>
    </dict>
  </array>
</dict></plist>
''');

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.singleWhere((f) => f.id == 'ios-custom-url-scheme').level,
      FindingLevel.warning,
    );
  });

  test('ci_required=false emits INFO for missing workflows', () async {
    final project = await _baseProject(
      tempRoot,
      'ci_optional',
      yamlExtra: '''
store_profile:
  ci_required: false
''',
    );

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.id == 'missing-ci-workflow',
    );
    expect(finding.level, FindingLevel.info);
    expect(finding.affectsScore, isFalse);
  });

  test('ci_required unspecified keeps missing-ci-workflow WARNING', () async {
    final project = await _baseProject(tempRoot, 'ci_required_default');
    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.singleWhere((f) => f.id == 'missing-ci-workflow').level,
      FindingLevel.warning,
    );
  });

  test('has_user_generated_content=false suppresses UGC warning', () async {
    final project = await _baseProject(
      tempRoot,
      'no_ugc',
      yamlExtra: '''
store_compliance:
  user_generated_content: true
store_profile:
  has_user_generated_content: false
''',
    );

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where((f) => f.id == 'apple-ugc-moderation-review'),
      isEmpty,
    );
  });

  test('confidence and guideline appear in console Markdown JSON', () async {
    final project = await _baseProject(
      tempRoot,
      'confidence_output',
      yamlExtra: '''
store_compliance:
  account_required: true
''',
    );

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.firstWhere(
      (f) => f.id == 'play-account-deletion-missing',
    );
    expect(finding.confidence, FindingConfidence.medium);
    expect(finding.guideline, 'Google Play Account Deletion');
    expect(report.toConsole(), contains('confidence='));
    expect(report.toMarkdown(), contains('Confidence:'));
    expect(report.toJsonString(), contains('"confidence"'));
    expect(report.toJsonString(), contains('manual_review'));
  });

  test('hard-coded secrets remain non-suppressible and high confidence',
      () async {
    final project = await _baseProject(
      tempRoot,
      'secret_nonsuppress',
      yamlExtra: '''
ignore:
  - hard-coded-secret
  - insecure-http
severity_overrides:
  hard-coded-secret: info
  insecure-http: info
''',
    );
    final lib = Directory('${project.path}${Platform.pathSeparator}lib');
    await lib.create(recursive: true);
    await File('${lib.path}${Platform.pathSeparator}leak.dart')
        .writeAsString('''
const apiKey = 'FAKESECRET_test_only_not_a_real_provider_key_0001';
const endpoint = 'http://api.example.com/v1';
''');

    final report = await ReleaseDoctor().check(project);
    final secret = report.findings.singleWhere(
      (f) => f.id == 'hard-coded-secret',
    );
    expect(secret.level, isNot(FindingLevel.info));
    expect(secret.confidence, FindingConfidence.high);
    final http = report.findings.singleWhere((f) => f.id == 'insecure-http');
    expect(http.level, isNot(FindingLevel.info));
    expect(http.confidence, FindingConfidence.high);
  });
}

Future<Directory> _baseProject(
  Directory tempRoot,
  String name, {
  String transactionType = 'unknown',
  String pubspecExtra = '',
  String yamlExtra = '',
}) async {
  final project = Directory('${tempRoot.path}${Platform.pathSeparator}$name');
  await project.create(recursive: true);
  await File('${project.path}${Platform.pathSeparator}pubspec.yaml')
      .writeAsString('''
name: $name
description: Fixture
version: 1.0.0+1
environment:
  sdk: ^3.5.0
$pubspecExtra
''');
  await File(
    '${project.path}${Platform.pathSeparator}.release-doctor.yaml',
  ).writeAsString('''
version: 1
transaction_type: $transactionType
$yamlExtra
''');
  return project;
}

Future<void> _writeAndroidManifest(Directory project, String contents) async {
  final dir = Directory(
    '${project.path}${Platform.pathSeparator}android'
    '${Platform.pathSeparator}app'
    '${Platform.pathSeparator}src'
    '${Platform.pathSeparator}main',
  );
  await dir.create(recursive: true);
  await File('${dir.path}${Platform.pathSeparator}AndroidManifest.xml')
      .writeAsString(contents);
}
