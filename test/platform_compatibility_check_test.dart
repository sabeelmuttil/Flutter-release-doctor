import 'dart:io';

import 'package:flutter_release_doctor/flutter_release_doctor.dart';
import 'package:test/test.dart';

void main() {
  late Directory tempRoot;

  setUp(() async {
    tempRoot = await Directory.systemTemp.createTemp('release_doctor_plat_');
  });

  tearDown(() async {
    if (await tempRoot.exists()) {
      await tempRoot.delete(recursive: true);
    }
  });

  test('PASS for valid Android SDK ordering', () async {
    final project = await _baseProject(tempRoot, 'sdk_valid');
    await _writeAndroidGradle(project, '''
android {
    compileSdk 35
    defaultConfig {
        minSdk 24
        targetSdk 35
    }
}
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.title == 'Android SDK levels',
    );
    expect(finding.level, FindingLevel.passed);
    expect(finding.detail, contains('minSdk=24'));
    expect(finding.detail, contains('targetSdk=35'));
    expect(finding.detail, contains('compileSdk=35'));
  });

  test('ERROR when Android SDK ordering is invalid', () async {
    final project = await _baseProject(tempRoot, 'sdk_invalid');
    await _writeAndroidGradle(project, '''
android {
    compileSdk 30
    defaultConfig {
        minSdk 34
        targetSdk 33
    }
}
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.title == 'Android SDK levels',
    );
    expect(finding.level, FindingLevel.error);
    expect(finding.detail, contains('minSdk=34'));
    expect(finding.detail, contains('targetSdk=33'));
    expect(finding.detail, contains('compileSdk=30'));
    expect(report.hasErrors, isTrue);
  });

  test('WARNING when Android SDK values cannot be resolved', () async {
    final project = await _baseProject(tempRoot, 'sdk_unresolved');
    await _writeAndroidGradle(project, '''
android {
    compileSdk = flutter.compileSdkVersion
    defaultConfig {
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
    }
}
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.title == 'Android SDK levels',
    );
    expect(finding.level, FindingLevel.warning);
    expect(finding.detail.toLowerCase(), contains('could not resolve'));
  });

  test('WARNING when usesCleartextTraffic is true', () async {
    final project = await _baseProject(tempRoot, 'cleartext');
    await _writeAndroidGradle(project, '''
android {
    compileSdk 35
    defaultConfig {
        minSdk 24
        targetSdk 35
    }
}
''');
    await _writeManifest(
      project,
      '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:usesCleartextTraffic="true" />
</manifest>
''',
    );

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.title == 'Android cleartext traffic',
    );
    expect(finding.level, FindingLevel.warning);
    expect(finding.detail, contains('usesCleartextTraffic'));
  });

  test('PASS for consistent iOS deployment target', () async {
    final project = await _baseProject(tempRoot, 'ios_target_valid');
    await _writeIosPbxproj(project, '''
DBG /* Debug */ = {
  isa = XCBuildConfiguration;
  buildSettings = {
    IPHONEOS_DEPLOYMENT_TARGET = 13.0;
  };
  name = Debug;
};
REL /* Release */ = {
  isa = XCBuildConfiguration;
  buildSettings = {
    IPHONEOS_DEPLOYMENT_TARGET = 13.0;
  };
  name = Release;
};
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.title == 'iOS deployment target',
    );
    expect(finding.level, FindingLevel.passed);
    expect(finding.detail, contains('13.0'));
  });

  test('WARNING when iOS deployment targets are inconsistent', () async {
    final project = await _baseProject(tempRoot, 'ios_target_inconsistent');
    await _writeIosPbxproj(project, '''
DBG /* Debug */ = {
  isa = XCBuildConfiguration;
  buildSettings = {
    IPHONEOS_DEPLOYMENT_TARGET = 12.0;
  };
  name = Debug;
};
REL /* Release */ = {
  isa = XCBuildConfiguration;
  buildSettings = {
    IPHONEOS_DEPLOYMENT_TARGET = 15.0;
  };
  name = Release;
};
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.title == 'iOS deployment target',
    );
    expect(finding.level, FindingLevel.warning);
    expect(finding.detail, contains('12.0'));
    expect(finding.detail, contains('15.0'));
  });

  test('WARNING when privacy-sensitive iOS usage lacks PrivacyInfo.xcprivacy',
      () async {
    final project = await _baseProject(tempRoot, 'privacy_missing');
    await _writeIosPbxproj(project, '''
REL /* Release */ = {
  isa = XCBuildConfiguration;
  buildSettings = {
    IPHONEOS_DEPLOYMENT_TARGET = 13.0;
  };
  name = Release;
};
''');
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
  <string>Camera access for scanning</string>
</dict>
</plist>
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.title == 'iOS privacy manifest',
    );
    expect(finding.level, FindingLevel.warning);
    expect(finding.detail, contains('PrivacyInfo.xcprivacy'));
  });

  test('PASS when PrivacyInfo.xcprivacy is present', () async {
    final project = await _baseProject(tempRoot, 'privacy_present');
    await _writeIosPbxproj(project, '''
REL /* Release */ = {
  isa = XCBuildConfiguration;
  buildSettings = {
    IPHONEOS_DEPLOYMENT_TARGET = 13.0;
  };
  name = Release;
};
''');
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
  <string>Camera access for scanning</string>
</dict>
</plist>
''');
    await File('${runner.path}${Platform.pathSeparator}PrivacyInfo.xcprivacy')
        .writeAsString('''
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>NSPrivacyAccessedAPITypes</key>
  <array/>
</dict>
</plist>
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.title == 'iOS privacy manifest',
    );
    expect(finding.level, FindingLevel.passed);
    expect(finding.detail, contains('PrivacyInfo.xcprivacy'));
    expect(finding.detail.toLowerCase(), contains('not validated'));
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

Future<void> _writeAndroidGradle(Directory project, String contents) async {
  final app = Directory(
    '${project.path}${Platform.pathSeparator}android${Platform.pathSeparator}app',
  );
  await app.create(recursive: true);
  await File('${app.path}${Platform.pathSeparator}build.gradle')
      .writeAsString(contents);
}

Future<void> _writeManifest(Directory project, String contents) async {
  final dir = Directory(
    '${project.path}${Platform.pathSeparator}android${Platform.pathSeparator}app${Platform.pathSeparator}src${Platform.pathSeparator}main',
  );
  await dir.create(recursive: true);
  await File('${dir.path}${Platform.pathSeparator}AndroidManifest.xml')
      .writeAsString(contents);
}

Future<void> _writeIosPbxproj(Directory project, String contents) async {
  final xcodeproj = Directory(
    '${project.path}${Platform.pathSeparator}ios${Platform.pathSeparator}Runner.xcodeproj',
  );
  await xcodeproj.create(recursive: true);
  await File(
    '${xcodeproj.path}${Platform.pathSeparator}project.pbxproj',
  ).writeAsString(contents);
}
