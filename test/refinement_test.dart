import 'dart:io';

import 'package:flutter_release_doctor/flutter_release_doctor.dart';
import 'package:test/test.dart';

void main() {
  late Directory tempRoot;

  setUp(() async {
    tempRoot = await Directory.systemTemp.createTemp('release_doctor_refine_');
  });

  tearDown(() async {
    if (await tempRoot.exists()) {
      await tempRoot.delete(recursive: true);
    }
  });

  test('security findings include file:line evidence and redact secrets',
      () async {
    final project = await _baseProject(tempRoot, 'evidence_security');
    final lib = Directory('${project.path}${Platform.pathSeparator}lib');
    await lib.create(recursive: true);
    await File('${lib.path}${Platform.pathSeparator}config.dart')
        .writeAsString('''
const endpoint = 'http://api.example.com/v1';
const api_key = 'abcdefghijklmnopqrstuvwxyz012345';
''');

    final report = await ReleaseDoctor().check(project);
    final http = report.findings.singleWhere((f) => f.id == 'insecure-http');
    expect(http.file, 'lib/config.dart');
    expect(http.line, isNotNull);
    expect(report.toConsole(), contains('lib/config.dart:'));
    expect(report.toMarkdown(), contains('lib/config.dart:'));

    final secret =
        report.findings.singleWhere((f) => f.id == 'hard-coded-secret');
    expect(secret.file, 'lib/config.dart');
    expect(secret.line, isNotNull);
    expect(secret.classification, isNotNull);
    expect(secret.detail.toLowerCase(), contains('redacted'));
    expect(report.toJsonString(),
        isNot(contains('abcdefghijklmnopqrstuvwxyz012345')));
    expect(report.toConsole(),
        isNot(contains('abcdefghijklmnopqrstuvwxyz012345')));
  });

  test('hard-coded API URL findings include file:line evidence', () async {
    final project = await _baseProject(tempRoot, 'evidence_api');
    final lib = Directory('${project.path}${Platform.pathSeparator}lib');
    await lib.create(recursive: true);
    await File('${lib.path}${Platform.pathSeparator}api.dart').writeAsString('''
class Api {
  static const apiBaseUrl = 'https://api.example.com/v1';
}
''');

    final report = await ReleaseDoctor().check(project);
    final finding =
        report.findings.singleWhere((f) => f.id == 'hard-coded-api-url');
    expect(finding.file, 'lib/api.dart');
    expect(finding.line, isNotNull);
    expect(finding.evidenceLabel, contains('lib/api.dart:'));
  });

  test('iOS bundle ID resolves Runner only and ignores extension targets',
      () async {
    final project = await _baseProject(tempRoot, 'runner_extension');
    await _writeIosBundleFixture(project);
    await File(
      '${project.path}${Platform.pathSeparator}ios${Platform.pathSeparator}Runner${Platform.pathSeparator}GoogleService-Info.plist',
    ).writeAsString('''
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>BUNDLE_ID</key>
  <string>inn.uae.chicking</string>
</dict>
</plist>
''');

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where(
        (f) =>
            f.id == 'ios-bundle-id' &&
            f.detail.contains('OneSignalNotificationServiceExtension'),
      ),
      isEmpty,
    );
    expect(
      report.findings.where(
        (f) =>
            f.id == 'ios-app-identity' &&
            f.level == FindingLevel.passed &&
            f.detail.contains('inn.uae.chicking'),
      ),
      isNotEmpty,
    );
  });

  test(
      'custom URL scheme intent filters do not trigger HTTPS App Link warnings',
      () async {
    final project = await _baseProject(tempRoot, 'custom_not_https');
    await _writeManifest(project, '''
<manifest>
  <application>
    <activity android:name=".MainActivity">
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="myapp" android:host="open" />
      </intent-filter>
    </activity>
  </application>
</manifest>
''');

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where((f) => f.id == 'android-app-links-host'),
      isEmpty,
    );
    expect(
      report.findings.where((f) => f.id == 'android-app-links-autoverify'),
      isEmpty,
    );
    expect(
      report.findings.where(
        (f) =>
            f.id == 'android-custom-url-scheme' &&
            f.level == FindingLevel.passed,
      ),
      isNotEmpty,
    );
  });

  test('HTTPS App Links warn for missing host with file:line evidence',
      () async {
    final project = await _baseProject(tempRoot, 'https_no_host');
    await _writeManifest(project, '''
<manifest>
  <application>
    <activity android:name=".MainActivity">
      <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https" />
      </intent-filter>
    </activity>
  </application>
</manifest>
''');

    final report = await ReleaseDoctor().check(project);
    final finding =
        report.findings.singleWhere((f) => f.id == 'android-app-links-host');
    expect(finding.level, FindingLevel.warning);
    expect(finding.file, contains('AndroidManifest.xml'));
    expect(finding.line, isNotNull);
  });

  test('FlutterDeepLinkingEnabled alone does not imply Universal Links',
      () async {
    final project = await _baseProject(tempRoot, 'no_universal_infer');
    final runner = Directory(
      '${project.path}${Platform.pathSeparator}ios${Platform.pathSeparator}Runner',
    );
    await runner.create(recursive: true);
    await Directory(
      '${project.path}${Platform.pathSeparator}ios${Platform.pathSeparator}Runner.xcodeproj',
    ).create(recursive: true);
    await File('${runner.path}${Platform.pathSeparator}Info.plist')
        .writeAsString('''
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>FlutterDeepLinkingEnabled</key>
  <true/>
  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleURLSchemes</key>
      <array>
        <string>myapp</string>
      </array>
    </dict>
  </array>
</dict>
</plist>
''');

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where((f) => f.id == 'ios-associated-domains'),
      isEmpty,
    );
  });

  test('Pods PrivacyInfo.xcprivacy does not count as app compliance', () async {
    final project = await _baseProject(tempRoot, 'pods_privacy');
    final runner = Directory(
      '${project.path}${Platform.pathSeparator}ios${Platform.pathSeparator}Runner',
    );
    await runner.create(recursive: true);
    await File('${runner.path}${Platform.pathSeparator}Info.plist')
        .writeAsString('''
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>NSCameraUsageDescription</key>
  <string>Camera</string>
</dict>
</plist>
''');
    final pods = Directory(
      '${project.path}${Platform.pathSeparator}ios${Platform.pathSeparator}Pods${Platform.pathSeparator}FirebaseCore',
    );
    await pods.create(recursive: true);
    await File('${pods.path}${Platform.pathSeparator}PrivacyInfo.xcprivacy')
        .writeAsString('''
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict></dict></plist>
''');

    final report = await ReleaseDoctor().check(project);
    final finding =
        report.findings.singleWhere((f) => f.id == 'ios-privacy-manifest');
    expect(finding.level, FindingLevel.warning);
    expect(finding.detail.toLowerCase(), contains('pods'));
    expect(finding.detail.toLowerCase(), contains('could not be confirmed'));
  });

  test('unresolved iOS URL scheme variables are WARNING not PASS', () async {
    final project = await _baseProject(tempRoot, 'ios_scheme_vars');
    final runner = Directory(
      '${project.path}${Platform.pathSeparator}ios${Platform.pathSeparator}Runner',
    );
    await runner.create(recursive: true);
    await File('${runner.path}${Platform.pathSeparator}Info.plist')
        .writeAsString('''
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleURLSchemes</key>
      <array>
        <string>amzn-\$(PRODUCT_BUNDLE_IDENTIFIER)</string>
        <string>\$(REVERSED_CLIENT_ID_KEY)</string>
      </array>
    </dict>
  </array>
</dict>
</plist>
''');

    final report = await ReleaseDoctor().check(project);
    final schemeFindings =
        report.findings.where((f) => f.id == 'ios-custom-url-scheme').toList();
    expect(
      schemeFindings.any((f) => f.level == FindingLevel.warning),
      isTrue,
    );
    expect(
      schemeFindings.any((f) => f.level == FindingLevel.manualReview),
      isTrue,
    );
    final warning =
        schemeFindings.singleWhere((f) => f.level == FindingLevel.warning);
    expect(warning.detail.toLowerCase(), contains('unresolved'));
    expect(warning.file, contains('Info.plist'));
    expect(report.toConsole(), isNot(contains('REVERSED_CLIENT_ID_KEY)')));
  });

  test('key.properties gitignore warning mentions git check-ignore', () async {
    final project = await _baseProject(tempRoot, 'keyprops_gitignore');
    final androidApp = Directory(
      '${project.path}${Platform.pathSeparator}android${Platform.pathSeparator}app',
    );
    await androidApp.create(recursive: true);
    await File('${androidApp.path}${Platform.pathSeparator}build.gradle')
        .writeAsString('''
def keystorePropertiesFile = rootProject.file('key.properties')
android {
    signingConfigs {
        release {
            keyAlias keystoreProperties['keyAlias']
        }
    }
    buildTypes {
        release {
            signingConfig signingConfigs.release
            minifyEnabled true
            shrinkResources true
        }
    }
}
''');
    await File(
      '${project.path}${Platform.pathSeparator}android${Platform.pathSeparator}key.properties',
    ).writeAsString('storePassword=secret\n');
    await File('${project.path}${Platform.pathSeparator}.gitignore')
        .writeAsString('.dart_tool/\n');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.id == 'android-key-properties-gitignore',
    );
    expect(finding.level, FindingLevel.warning);
    expect(finding.detail, contains('git check-ignore -v'));
  });
}

Future<Directory> _baseProject(Directory tempRoot, String name) async {
  final project = Directory('${tempRoot.path}${Platform.pathSeparator}$name');
  await project.create(recursive: true);
  await File('${project.path}${Platform.pathSeparator}pubspec.yaml')
      .writeAsString('''
name: $name
description: Fixture
version: 1.0.0+1
environment:
  sdk: ^3.5.0
''');
  return project;
}

Future<void> _writeManifest(Directory project, String contents) async {
  final dir = Directory(
    '${project.path}${Platform.pathSeparator}android${Platform.pathSeparator}app${Platform.pathSeparator}src${Platform.pathSeparator}main',
  );
  await dir.create(recursive: true);
  await File('${dir.path}${Platform.pathSeparator}AndroidManifest.xml')
      .writeAsString(contents);
}

Future<void> _writeIosBundleFixture(Directory project) async {
  final xcodeproj = Directory(
    '${project.path}${Platform.pathSeparator}ios${Platform.pathSeparator}Runner.xcodeproj',
  );
  final runner = Directory(
    '${project.path}${Platform.pathSeparator}ios${Platform.pathSeparator}Runner',
  );
  await xcodeproj.create(recursive: true);
  await runner.create(recursive: true);
  await File('${runner.path}${Platform.pathSeparator}Info.plist')
      .writeAsString('''
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>\$(PRODUCT_BUNDLE_IDENTIFIER)</string>
</dict>
</plist>
''');
  await File('${xcodeproj.path}${Platform.pathSeparator}project.pbxproj')
      .writeAsString(r'''
/* Begin PBXNativeTarget section */
AAAAAAAAAAAAAAAARUNNER01 /* Runner */ = {
  isa = PBXNativeTarget;
  buildConfigurationList = BBBBBBBBBBBBBBBBRUNNERL1 /* Build configuration list for PBXNativeTarget "Runner" */;
  name = Runner;
};
CCCCCCCCCCCCCCCCOSEXT001 /* OneSignalNotificationServiceExtension */ = {
  isa = PBXNativeTarget;
  buildConfigurationList = DDDDDDDDDDDDDDDDOSEXTL01 /* Build configuration list for PBXNativeTarget "OneSignalNotificationServiceExtension" */;
  name = OneSignalNotificationServiceExtension;
};
/* End PBXNativeTarget section */

BBBBBBBBBBBBBBBBRUNNERL1 /* Build configuration list for PBXNativeTarget "Runner" */ = {
  isa = XCConfigurationList;
  buildConfigurations = (
    EEEEEEEEEEEEEEEERUNDBG1 /* Debug */,
    FFFFFFFFFFFFFFFFRUNREL1 /* Release */,
  );
};

DDDDDDDDDDDDDDDDOSEXTL01 /* Build configuration list for PBXNativeTarget "OneSignalNotificationServiceExtension" */ = {
  isa = XCConfigurationList;
  buildConfigurations = (
    GGGGGGGGGGGGGGGGEXTDBG1 /* Debug */,
    HHHHHHHHHHHHHHHEXTREL1 /* Release */,
  );
};

EEEEEEEEEEEEEEEERUNDBG1 /* Debug */ = {
  isa = XCBuildConfiguration;
  buildSettings = {
    PRODUCT_BUNDLE_IDENTIFIER = inn.uae.chicking;
  };
  name = Debug;
};
FFFFFFFFFFFFFFFFRUNREL1 /* Release */ = {
  isa = XCBuildConfiguration;
  buildSettings = {
    PRODUCT_BUNDLE_IDENTIFIER = inn.uae.chicking;
  };
  name = Release;
};
GGGGGGGGGGGGGGGGEXTDBG1 /* Debug */ = {
  isa = XCBuildConfiguration;
  buildSettings = {
    PRODUCT_BUNDLE_IDENTIFIER = inn.uae.chicking.OneSignalNotificationServiceExtension;
  };
  name = Debug;
};
HHHHHHHHHHHHHHHEXTREL1 /* Release */ = {
  isa = XCBuildConfiguration;
  buildSettings = {
    PRODUCT_BUNDLE_IDENTIFIER = inn.uae.chicking.OneSignalNotificationServiceExtension;
  };
  name = Release;
};
''');
}
