import 'dart:io';

import 'package:flutter_release_doctor/flutter_release_doctor.dart';
import 'package:test/test.dart';

void main() {
  late Directory tempRoot;

  setUp(() async {
    tempRoot =
        await Directory.systemTemp.createTemp('release_doctor_deeplink_');
  });

  tearDown(() async {
    if (await tempRoot.exists()) {
      await tempRoot.delete(recursive: true);
    }
  });

  test('PASS for valid Android App Links', () async {
    final project = await _baseProject(tempRoot, 'android_applinks_valid');
    await _writeManifest(project, '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application>
    <activity android:name=".MainActivity">
      <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https" android:host="app.example.com" />
      </intent-filter>
    </activity>
  </application>
</manifest>
''');

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where(
        (f) => f.title == 'Android App Links' && f.level == FindingLevel.passed,
      ),
      isNotEmpty,
    );
  });

  test('WARNING when Android HTTPS deep link lacks autoVerify', () async {
    final project = await _baseProject(tempRoot, 'android_no_autoverify');
    await _writeManifest(project, '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application>
    <activity android:name=".MainActivity">
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https" android:host="app.example.com" />
      </intent-filter>
    </activity>
  </application>
</manifest>
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.title == 'Android App Links autoVerify',
    );
    expect(finding.level, FindingLevel.warning);
    expect(finding.detail, contains('autoVerify'));
  });

  test('PASS for valid iOS associated domains', () async {
    final project = await _baseProject(tempRoot, 'ios_applinks_valid');
    await _writeIosSkeleton(project);
    await File(
      '${project.path}${Platform.pathSeparator}ios${Platform.pathSeparator}Runner${Platform.pathSeparator}Runner.entitlements',
    ).writeAsString('''
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>com.apple.developer.associated-domains</key>
  <array>
    <string>applinks:app.example.com</string>
  </array>
</dict>
</plist>
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.title == 'iOS associated domains',
    );
    expect(finding.level, FindingLevel.passed);
    expect(finding.detail, contains('app.example.com'));
  });

  test('WARNING when iOS associated domains entitlements are missing',
      () async {
    final project = await _baseProject(tempRoot, 'ios_applinks_missing');
    await _writeIosSkeleton(project);
    await File(
      '${project.path}${Platform.pathSeparator}ios${Platform.pathSeparator}Runner${Platform.pathSeparator}Runner.entitlements',
    ).writeAsString('''
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>com.apple.developer.associated-domains</key>
  <array>
  </array>
</dict>
</plist>
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.title == 'iOS associated domains',
    );
    expect(finding.level, FindingLevel.warning);
    expect(finding.detail.toLowerCase(), contains('applinks'));
  });

  test('PASS for valid custom URL schemes on Android and iOS', () async {
    final project = await _baseProject(tempRoot, 'custom_schemes');
    await _writeManifest(project, '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application>
    <activity android:name=".MainActivity">
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="myapp" />
      </intent-filter>
    </activity>
  </application>
</manifest>
''');
    await _writeIosSkeleton(project);
    await File(
      '${project.path}${Platform.pathSeparator}ios${Platform.pathSeparator}Runner${Platform.pathSeparator}Info.plist',
    ).writeAsString('''
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
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
      report.findings.where(
        (f) =>
            f.title == 'Android custom URL scheme' &&
            f.level == FindingLevel.passed &&
            f.detail.contains('myapp'),
      ),
      isNotEmpty,
    );
    expect(
      report.findings.where(
        (f) =>
            f.title == 'iOS custom URL scheme' &&
            f.level == FindingLevel.passed &&
            f.detail.contains('myapp') &&
            !f.detail.contains('?'),
      ),
      isNotEmpty,
    );
  });

  test('WARNING when Firebase Messaging lacks notification setup', () async {
    final project = await _baseProject(
      tempRoot,
      'fcm_missing',
      pubspecExtra: '''
dependencies:
  firebase_messaging: ^15.0.0
''',
    );
    await _writeAndroidGradle(project, '''
android {
    compileSdk 35
    defaultConfig {
        minSdk 24
        targetSdk 35
    }
}
''');
    await _writeManifest(project, '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application />
</manifest>
''');
    await _writeIosSkeleton(project);
    await File(
      '${project.path}${Platform.pathSeparator}ios${Platform.pathSeparator}Runner${Platform.pathSeparator}Runner.entitlements',
    ).writeAsString('''
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
</dict>
</plist>
''');

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where(
        (f) =>
            f.title == 'Android push notifications' &&
            f.level == FindingLevel.warning &&
            f.detail.contains('POST_NOTIFICATIONS'),
      ),
      isNotEmpty,
    );
    expect(
      report.findings.where(
        (f) =>
            f.title == 'iOS push notifications' &&
            f.level == FindingLevel.warning &&
            f.detail.contains('aps-environment'),
      ),
      isNotEmpty,
    );

    final blob = '${report.toConsole()}\n${report.toMarkdown()}';
    expect(blob.toLowerCase(), isNot(contains('token')));
    expect(blob.toLowerCase(), isNot(contains('apns')));
  });

  test('PASS when Firebase Messaging push setup is complete', () async {
    final project = await _baseProject(
      tempRoot,
      'fcm_valid',
      pubspecExtra: '''
dependencies:
  firebase_messaging: ^15.0.0
''',
    );
    await _writeAndroidGradle(project, '''
android {
    compileSdk 35
    defaultConfig {
        minSdk 24
        targetSdk 35
    }
}
''');
    await _writeManifest(project, '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
  <application />
</manifest>
''');
    await _writeIosSkeleton(project);
    await File(
      '${project.path}${Platform.pathSeparator}ios${Platform.pathSeparator}Runner${Platform.pathSeparator}Runner.entitlements',
    ).writeAsString('''
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>aps-environment</key>
  <string>production</string>
</dict>
</plist>
''');

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where(
        (f) =>
            f.title == 'Android push notifications' &&
            f.level == FindingLevel.passed,
      ),
      isNotEmpty,
    );
    expect(
      report.findings.where(
        (f) =>
            f.title == 'iOS push notifications' &&
            f.level == FindingLevel.passed,
      ),
      isNotEmpty,
    );
  });
}

Future<Directory> _baseProject(
  Directory tempRoot,
  String name, {
  String pubspecExtra = '',
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

Future<void> _writeAndroidGradle(Directory project, String contents) async {
  final app = Directory(
    '${project.path}${Platform.pathSeparator}android${Platform.pathSeparator}app',
  );
  await app.create(recursive: true);
  await File('${app.path}${Platform.pathSeparator}build.gradle')
      .writeAsString(contents);
}

Future<void> _writeIosSkeleton(Directory project) async {
  final runner = Directory(
    '${project.path}${Platform.pathSeparator}ios${Platform.pathSeparator}Runner',
  );
  final xcodeproj = Directory(
    '${project.path}${Platform.pathSeparator}ios${Platform.pathSeparator}Runner.xcodeproj',
  );
  await runner.create(recursive: true);
  await xcodeproj.create(recursive: true);
  await File(
    '${xcodeproj.path}${Platform.pathSeparator}project.pbxproj',
  ).writeAsString('''
REL /* Release */ = {
  isa = XCBuildConfiguration;
  buildSettings = {
    IPHONEOS_DEPLOYMENT_TARGET = 13.0;
  };
  name = Release;
};
''');
}
