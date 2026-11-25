import 'dart:io';

import 'package:flutter_release_doctor/flutter_release_doctor.dart';
import 'package:test/test.dart';

void main() {
  late Directory tempRoot;

  setUp(() async {
    tempRoot =
        await Directory.systemTemp.createTemp('release_doctor_store_comp_');
  });

  tearDown(() async {
    if (await tempRoot.exists()) {
      await tempRoot.delete(recursive: true);
    }
  });

  test('disclaimer appears in console, Markdown, and JSON', () async {
    final project = await _baseProject(tempRoot, 'disclaimer');
    final report = await ReleaseDoctor().check(project);
    const text = DoctorReport.storeRiskDisclaimer;
    expect(report.toConsole(), contains(text));
    expect(report.toMarkdown(), contains(text));
    expect(report.toJsonString(), contains(text));
    expect(
      report.findings.any((f) => f.id == 'store-guideline-risk-disclaimer'),
      isTrue,
    );
  });

  test('Play WARNING when sensitive permissions lack privacy_policy_url',
      () async {
    final project = await _baseProject(tempRoot, 'play_privacy_missing');
    await _writeAndroidManifest(project, '''
<manifest>
  <uses-permission android:name="android.permission.CAMERA" />
</manifest>
''');

    final report = await ReleaseDoctor().check(project);
    final f = report.findings.singleWhere(
      (x) => x.id == 'play-privacy-policy-missing',
    );
    expect(f.level, FindingLevel.warning);
    expect(f.detail.toLowerCase(), contains('privacy'));
    expect(f.file, contains('AndroidManifest.xml'));
  });

  test('Play Data Safety review when analytics/Firebase detected', () async {
    final project = await _baseProject(
      tempRoot,
      'play_data_safety',
      pubspecExtra: '''
dependencies:
  firebase_analytics: ^11.0.0
''',
    );

    final report = await ReleaseDoctor().check(project);
    final f = report.findings.singleWhere(
      (x) => x.id == 'play-data-safety-review',
    );
    expect(f.level, FindingLevel.manualReview);
    expect(f.confidence, FindingConfidence.low);
    expect(f.detail, contains('manually'));
    expect(f.detail, contains('never claims Data Safety forms are complete'));
  });

  test('Play WARNING when account_required without deletion URL', () async {
    final project = await _baseProject(
      tempRoot,
      'play_account_deletion',
      storeYaml: '''
store_compliance:
  account_required: true
''',
    );

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings
          .singleWhere((f) => f.id == 'play-account-deletion-missing')
          .level,
      FindingLevel.warning,
    );
  });

  test('Play billing bypass risk for digital_goods with external payment',
      () async {
    final project = await _baseProject(
      tempRoot,
      'play_bypass',
      transactionType: 'digital_goods',
      pubspecExtra: '''
dependencies:
  razorpay_flutter: ^1.3.0
''',
    );

    final report = await ReleaseDoctor().check(project);
    final f = report.findings.singleWhere(
      (x) => x.id == 'play-billing-bypass-risk',
    );
    expect(f.level, FindingLevel.warning);
    expect(f.detail.toLowerCase(), contains('play billing'));
  });

  test('Play PASS for physical_goods external payments permitted', () async {
    final project = await _baseProject(
      tempRoot,
      'play_physical',
      transactionType: 'physical_goods',
    );

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings
          .singleWhere(
            (f) => f.id == 'play-physical-goods-payments-allowed',
          )
          .level,
      FindingLevel.passed,
    );
    expect(
      report.findings.where((f) => f.id == 'play-billing-bypass-risk'),
      isEmpty,
    );
  });

  test('Play INFO when Families / audience cannot be determined', () async {
    final project = await _baseProject(tempRoot, 'play_families');
    final report = await ReleaseDoctor().check(project);
    final f = report.findings.singleWhere(
      (x) => x.id == 'play-families-audience-unknown',
    );
    expect(f.level, FindingLevel.info);
    expect(f.detail.toLowerCase(), contains('cannot be determined'));
  });

  test('Apple WARNING when iOS privacy keys lack privacy_policy_url', () async {
    final project = await _baseProject(tempRoot, 'apple_privacy_missing');
    await _writeInfoPlist(project, '''
<plist><dict>
  <key>NSCameraUsageDescription</key>
  <string>Camera for scans</string>
</dict></plist>
''');

    final report = await ReleaseDoctor().check(project);
    final f = report.findings.singleWhere(
      (x) => x.id == 'apple-privacy-policy-missing',
    );
    expect(f.level, FindingLevel.warning);
    expect(f.detail, contains('5.1.1'));
  });

  test('Apple WARNING when account_required without deletion URL', () async {
    final project = await _baseProject(
      tempRoot,
      'apple_account_deletion',
      storeYaml: '''
store_compliance:
  account_required: true
''',
    );

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings
          .singleWhere((f) => f.id == 'apple-account-deletion-missing')
          .level,
      FindingLevel.warning,
    );
  });

  test('Apple WARNING when social login lacks Sign in with Apple', () async {
    final project = await _baseProject(
      tempRoot,
      'apple_siwa_missing',
      pubspecExtra: '''
dependencies:
  google_sign_in: ^6.0.0
''',
    );

    final report = await ReleaseDoctor().check(project);
    final f = report.findings.singleWhere(
      (x) =>
          x.id == 'apple-sign-in-with-apple-review' &&
          x.level == FindingLevel.warning,
    );
    expect(f.detail, contains('4.8'));
  });

  test('Apple does not warn SIWA for own email/password login only', () async {
    final project = await _baseProject(tempRoot, 'apple_own_auth');
    await _writeLib(project, 'auth.dart', '''
Future<void> login(String email, String password) async {
  await signInWithEmailAndPassword(email, password);
}
Future<void> signInWithEmailAndPassword(String e, String p) async {}
''');

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where(
        (f) =>
            f.id == 'apple-sign-in-with-apple-review' &&
            f.level == FindingLevel.warning,
      ),
      isEmpty,
    );
    final info = report.findings.singleWhere(
      (f) =>
          f.id == 'apple-sign-in-with-apple-review' &&
          f.level == FindingLevel.info,
    );
    expect(info.detail.toLowerCase(), contains('evidence limitations'));
  });

  test('Apple WARNING when ads present but uses_tracking undeclared', () async {
    final project = await _baseProject(
      tempRoot,
      'apple_tracking_undeclared',
      pubspecExtra: '''
dependencies:
  google_mobile_ads: ^5.0.0
''',
    );

    final report = await ReleaseDoctor().check(project);
    final f = report.findings.singleWhere(
      (x) => x.id == 'apple-att-review' && x.level == FindingLevel.warning,
    );
    expect(f.detail, contains('uses_tracking'));
  });

  test('Apple WARNING when uses_tracking true without ATT description',
      () async {
    final project = await _baseProject(
      tempRoot,
      'apple_att_missing',
      storeYaml: '''
store_compliance:
  uses_tracking: true
''',
    );
    await _writeInfoPlist(project, '''
<plist><dict>
  <key>CFBundleName</key>
  <string>App</string>
</dict></plist>
''');

    final report = await ReleaseDoctor().check(project);
    final f = report.findings.singleWhere((x) => x.id == 'apple-att-review');
    expect(f.level, FindingLevel.warning);
    expect(f.detail, contains('NSUserTrackingUsageDescription'));
  });

  test('Apple WARNING when digital_goods lacks IAP support', () async {
    final project = await _baseProject(
      tempRoot,
      'apple_iap_missing',
      transactionType: 'subscription',
    );

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.singleWhere((f) => f.id == 'apple-iap-missing').level,
      FindingLevel.warning,
    );
  });

  test('Apple PASS for physical_goods external payments', () async {
    final project = await _baseProject(
      tempRoot,
      'apple_physical',
      transactionType: 'physical_goods',
    );

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings
          .singleWhere((f) => f.id == 'apple-physical-goods-payments-allowed')
          .level,
      FindingLevel.passed,
    );
  });

  test('Apple WARNING when reviewer demo account missing', () async {
    final project = await _baseProject(
      tempRoot,
      'apple_reviewer',
      storeYaml: '''
store_compliance:
  account_required: true
  account_deletion_url: https://example.com/delete
  reviewer_access:
    demo_account_provided: false
''',
    );

    final report = await ReleaseDoctor().check(project);
    final f = report.findings.singleWhere(
      (x) => x.id == 'apple-reviewer-access-missing',
    );
    expect(f.level, FindingLevel.warning);
    expect(f.detail, contains('2.1'));
  });

  test('Apple UGC moderation review when user_generated_content true',
      () async {
    final project = await _baseProject(
      tempRoot,
      'apple_ugc',
      storeYaml: '''
store_compliance:
  user_generated_content: true
''',
    );

    final report = await ReleaseDoctor().check(project);
    final f = report.findings.singleWhere(
      (x) => x.id == 'apple-ugc-moderation-review',
    );
    expect(f.level, FindingLevel.manualReview);
    expect(f.detail, contains('1.2'));
  });

  test('privacy_policy_url suppresses Play and Apple privacy missing',
      () async {
    final project = await _baseProject(
      tempRoot,
      'privacy_ok',
      storeYaml: '''
store_compliance:
  privacy_policy_url: https://example.com/privacy
''',
    );
    await _writeAndroidManifest(project, '''
<manifest>
  <uses-permission android:name="android.permission.CAMERA" />
</manifest>
''');
    await _writeInfoPlist(project, '''
<plist><dict>
  <key>NSCameraUsageDescription</key>
  <string>Camera</string>
</dict></plist>
''');

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where((f) => f.id == 'play-privacy-policy-missing'),
      isEmpty,
    );
    expect(
      report.findings.where((f) => f.id == 'apple-privacy-policy-missing'),
      isEmpty,
    );
  });
}

Future<Directory> _baseProject(
  Directory tempRoot,
  String name, {
  String transactionType = 'unknown',
  String pubspecExtra = '',
  String storeYaml = '',
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
$storeYaml
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

Future<void> _writeInfoPlist(Directory project, String contents) async {
  final dir = Directory(
    '${project.path}${Platform.pathSeparator}ios'
    '${Platform.pathSeparator}Runner',
  );
  await dir.create(recursive: true);
  await File('${dir.path}${Platform.pathSeparator}Info.plist')
      .writeAsString(contents);
}

Future<void> _writeLib(Directory project, String name, String contents) async {
  final lib = Directory('${project.path}${Platform.pathSeparator}lib');
  await lib.create(recursive: true);
  await File('${lib.path}${Platform.pathSeparator}$name')
      .writeAsString(contents);
}
