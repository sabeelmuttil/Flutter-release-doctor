import 'dart:io';

import 'package:flutter_release_doctor/flutter_release_doctor.dart';
import 'package:test/test.dart';

void main() {
  late Directory tempRoot;

  setUp(() async {
    tempRoot = await Directory.systemTemp.createTemp('release_doctor_');
  });

  tearDown(() async {
    if (await tempRoot.exists()) {
      await tempRoot.delete(recursive: true);
    }
  });

  test('PASS when Android and iOS IDs match their Firebase configs', () async {
    final project = await _createFixture(
      tempRoot,
      name: 'pass_case',
      androidAppId: 'com.example.pass',
      androidFirebasePackage: 'com.example.pass',
      iosBundleId: 'com.example.pass',
      iosFirebaseBundleId: 'com.example.pass',
      resolveIosViaPbxproj: true,
    );

    final report = await ReleaseDoctor().check(project);
    final titles = report.findings.map((f) => f.title).toList();

    expect(
      report.findings.where(
        (f) =>
            f.title == 'Android app identity' && f.level == FindingLevel.passed,
      ),
      isNotEmpty,
    );
    expect(
      report.findings.where(
        (f) => f.title == 'iOS app identity' && f.level == FindingLevel.passed,
      ),
      isNotEmpty,
    );
    expect(titles, isNot(contains('Android Firebase config')));
    expect(titles, isNot(contains('iOS Firebase config')));
  });

  test('ERROR when Android or iOS IDs mismatch Firebase configs', () async {
    final project = await _createFixture(
      tempRoot,
      name: 'mismatch_case',
      androidAppId: 'com.example.app',
      androidFirebasePackage: 'com.example.staging',
      iosBundleId: 'com.example.app',
      iosFirebaseBundleId: 'com.example.staging',
      resolveIosViaPbxproj: true,
    );

    final report = await ReleaseDoctor().check(project);
    final android = report.findings.singleWhere(
      (f) => f.title == 'Android app identity',
    );
    final ios = report.findings.singleWhere(
      (f) => f.title == 'iOS app identity',
    );

    expect(android.level, FindingLevel.error);
    expect(android.detail, contains('com.example.app'));
    expect(android.detail, contains('com.example.staging'));
    expect(android.fix, contains('google-services.json'));

    expect(ios.level, FindingLevel.error);
    expect(ios.detail, contains('com.example.app'));
    expect(ios.detail, contains('com.example.staging'));
    expect(ios.fix, contains('GoogleService-Info.plist'));
    expect(report.hasErrors, isTrue);
  });

  test('WARNING when platform folders exist without Firebase configs',
      () async {
    final project = await _createFixture(
      tempRoot,
      name: 'missing_firebase',
      androidAppId: 'com.example.app',
      iosBundleId: 'com.example.app',
      resolveIosViaPbxproj: true,
      includeAndroidFirebase: false,
      includeIosFirebase: false,
    );

    final report = await ReleaseDoctor().check(project);

    expect(
      report.findings.where(
        (f) =>
            f.title == 'Android Firebase config' &&
            f.level == FindingLevel.warning,
      ),
      isNotEmpty,
    );
    expect(
      report.findings.where(
        (f) =>
            f.title == 'iOS Firebase config' && f.level == FindingLevel.warning,
      ),
      isNotEmpty,
    );
    expect(
      report.findings.where((f) => f.title == 'Android app identity'),
      isEmpty,
    );
    expect(
      report.findings.where((f) => f.title == 'iOS app identity'),
      isEmpty,
    );
  });

  test('WARNING when Gradle or Xcode IDs use unresolved variables', () async {
    final project = await _createFixture(
      tempRoot,
      name: 'unresolved_vars',
      androidAppId: 'project.APPLICATION_ID',
      androidAppIdQuoted: false,
      androidFirebasePackage: 'com.example.app',
      iosBundleId: r'$(PRODUCT_BUNDLE_IDENTIFIER)',
      iosFirebaseBundleId: 'com.example.app',
      pbxprojBundleId: r'$(BUNDLE_ID_FROM_XCCONFIG)',
      resolveIosViaPbxproj: true,
    );

    final report = await ReleaseDoctor().check(project);

    final android = report.findings.singleWhere(
      (f) => f.title == 'Android app ID',
    );
    final ios = report.findings.singleWhere((f) => f.title == 'iOS bundle ID');

    expect(android.level, FindingLevel.warning);
    expect(android.detail, contains('applicationId'));
    expect(android.detail, contains('project.APPLICATION_ID'));

    expect(ios.level, FindingLevel.warning);
    expect(ios.detail, contains('PRODUCT_BUNDLE_IDENTIFIER'));
    expect(
      report.findings.where((f) => f.title == 'Android app identity'),
      isEmpty,
    );
    expect(
      report.findings.where((f) => f.title == 'iOS app identity'),
      isEmpty,
    );
  });

  test('reads Android applicationId from build.gradle.kts', () async {
    final project = await _createFixture(
      tempRoot,
      name: 'kts_case',
      androidAppId: 'com.example.kts',
      androidFirebasePackage: 'com.example.kts',
      useKotlinGradle: true,
      includeIos: false,
    );

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where(
        (f) =>
            f.title == 'Android app identity' &&
            f.level == FindingLevel.passed &&
            f.detail.contains('com.example.kts'),
      ),
      isNotEmpty,
    );
  });

  test('falls back to AndroidManifest package when Gradle has no applicationId',
      () async {
    final project = await _createFixture(
      tempRoot,
      name: 'manifest_fallback',
      androidFirebasePackage: 'com.example.manifest',
      androidManifestPackage: 'com.example.manifest',
      includeGradleApplicationId: false,
      includeIos: false,
    );

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where(
        (f) =>
            f.title == 'Android app identity' &&
            f.level == FindingLevel.passed &&
            f.detail.contains('com.example.manifest'),
      ),
      isNotEmpty,
    );
  });
}

Future<Directory> _createFixture(
  Directory tempRoot, {
  required String name,
  String? androidAppId,
  bool androidAppIdQuoted = true,
  String? androidFirebasePackage,
  String? androidManifestPackage,
  bool includeGradleApplicationId = true,
  bool useKotlinGradle = false,
  bool includeAndroidFirebase = true,
  String? iosBundleId,
  String? iosFirebaseBundleId,
  String? pbxprojBundleId,
  bool resolveIosViaPbxproj = false,
  bool includeIosFirebase = true,
  bool includeIos = true,
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
''');

  final androidApp = Directory(
    '${project.path}${Platform.pathSeparator}android${Platform.pathSeparator}app',
  );
  await androidApp.create(recursive: true);

  if (includeGradleApplicationId && androidAppId != null) {
    final gradleName = useKotlinGradle ? 'build.gradle.kts' : 'build.gradle';
    final assignment = androidAppIdQuoted
        ? (useKotlinGradle
            ? 'applicationId = "$androidAppId"'
            : 'applicationId "$androidAppId"')
        : 'applicationId = $androidAppId';
    await File(
      '${androidApp.path}${Platform.pathSeparator}$gradleName',
    ).writeAsString('''
android {
    defaultConfig {
        $assignment
    }
}
''');
  } else {
    await File(
      '${androidApp.path}${Platform.pathSeparator}build.gradle',
    ).writeAsString('''
android {
    namespace "com.example.namespaceonly"
}
''');
  }

  final manifestDir = Directory(
    '${androidApp.path}${Platform.pathSeparator}src${Platform.pathSeparator}main',
  );
  await manifestDir.create(recursive: true);
  final packageAttr = androidManifestPackage == null
      ? ''
      : ' package="$androidManifestPackage"';
  await File(
    '${manifestDir.path}${Platform.pathSeparator}AndroidManifest.xml',
  ).writeAsString('<manifest$packageAttr></manifest>\n');

  if (includeAndroidFirebase && androidFirebasePackage != null) {
    await File(
      '${androidApp.path}${Platform.pathSeparator}google-services.json',
    ).writeAsString('''
{
  "client": [
    {
      "client_info": {
        "android_client_info": {
          "package_name": "$androidFirebasePackage"
        }
      }
    }
  ]
}
''');
  }

  if (!includeIos) return project;

  final iosRunner = Directory(
    '${project.path}${Platform.pathSeparator}ios${Platform.pathSeparator}Runner',
  );
  await iosRunner.create(recursive: true);

  final infoBundleId = resolveIosViaPbxproj
      ? r'$(PRODUCT_BUNDLE_IDENTIFIER)'
      : (iosBundleId ?? 'com.example.app');
  await File(
    '${iosRunner.path}${Platform.pathSeparator}Info.plist',
  ).writeAsString('''
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>$infoBundleId</string>
</dict>
</plist>
''');

  if (resolveIosViaPbxproj) {
    final xcodeproj = Directory(
      '${project.path}${Platform.pathSeparator}ios${Platform.pathSeparator}Runner.xcodeproj',
    );
    await xcodeproj.create(recursive: true);
    final resolved = pbxprojBundleId ?? iosBundleId ?? 'com.example.app';
    await File(
      '${xcodeproj.path}${Platform.pathSeparator}project.pbxproj',
    ).writeAsString('''
buildSettings = {
  PRODUCT_BUNDLE_IDENTIFIER = $resolved;
};
buildSettings = {
  PRODUCT_BUNDLE_IDENTIFIER = $resolved.RunnerTests;
};
''');
  }

  if (includeIosFirebase && iosFirebaseBundleId != null) {
    await File(
      '${iosRunner.path}${Platform.pathSeparator}GoogleService-Info.plist',
    ).writeAsString('''
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>BUNDLE_ID</key>
	<string>$iosFirebaseBundleId</string>
</dict>
</plist>
''');
  }

  return project;
}
