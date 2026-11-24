import 'dart:io';

import 'package:flutter_release_doctor/flutter_release_doctor.dart';
import 'package:test/test.dart';

void main() {
  late Directory tempRoot;

  setUp(() async {
    tempRoot = await Directory.systemTemp.createTemp('release_doctor_sign_');
  });

  tearDown(() async {
    if (await tempRoot.exists()) {
      await tempRoot.delete(recursive: true);
    }
  });

  test('PASS for valid Android release signing setup', () async {
    final project = await _baseProject(tempRoot, 'android_valid');
    await _writeAndroidGradle(
      project,
      '''
def keystoreProperties = new Properties()
def keystorePropertiesFile = rootProject.file('key.properties')
if (keystorePropertiesFile.exists()) {
    keystoreProperties.load(new FileInputStream(keystorePropertiesFile))
}

android {
    signingConfigs {
        release {
            keyAlias keystoreProperties['keyAlias']
            keyPassword keystoreProperties['keyPassword']
            storeFile keystoreProperties['storeFile'] ? file(keystoreProperties['storeFile']) : null
            storePassword keystoreProperties['storePassword']
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
''',
    );
    await File(
      '${project.path}${Platform.pathSeparator}android${Platform.pathSeparator}key.properties',
    ).writeAsString('''
storePassword=should-never-leak
keyPassword=should-never-leak
keyAlias=upload
storeFile=upload-keystore.jks
''');
    await File('${project.path}${Platform.pathSeparator}.gitignore')
        .writeAsString('key.properties\n');

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where(
        (f) =>
            f.title == 'Android release signing' &&
            f.level == FindingLevel.passed,
      ),
      isNotEmpty,
    );
    expect(
      report.findings.where(
        (f) =>
            f.title == 'Android release minification' &&
            f.level == FindingLevel.passed,
      ),
      isNotEmpty,
    );
    expect(
      report.findings.where(
        (f) => f.title == 'Android key.properties gitignore',
      ),
      isEmpty,
    );

    final blob = '${report.toConsole()}\n${report.toMarkdown()}';
    expect(blob, isNot(contains('should-never-leak')));
    expect(blob, isNot(contains('upload-keystore.jks')));
  });

  test('ERROR when release build uses signingConfigs.debug', () async {
    final project = await _baseProject(tempRoot, 'android_debug_sign');
    await _writeAndroidGradle(
      project,
      '''
android {
    buildTypes {
        release {
            signingConfig signingConfigs.debug
        }
    }
}
''',
    );

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.title == 'Android release signing',
    );
    expect(finding.level, FindingLevel.error);
    expect(finding.detail, contains('signingConfigs.debug'));
    expect(report.hasErrors, isTrue);
  });

  test('WARNING when key.properties exists but is not gitignored', () async {
    final project = await _baseProject(tempRoot, 'android_gitignore');
    await _writeAndroidGradle(
      project,
      '''
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
''',
    );
    await File(
      '${project.path}${Platform.pathSeparator}android${Platform.pathSeparator}key.properties',
    ).writeAsString('storePassword=secret\nkeyPassword=secret\n');
    await File('${project.path}${Platform.pathSeparator}.gitignore')
        .writeAsString('.dart_tool/\n');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.title == 'Android key.properties gitignore',
    );
    expect(finding.level, FindingLevel.warning);
    expect(finding.detail, contains('key.properties'));
    expect(finding.detail, isNot(contains('secret')));
  });

  test('WARNING when Android Gradle signing setup is unresolved', () async {
    final project = await _baseProject(tempRoot, 'android_unresolved');
    await Directory(
      '${project.path}${Platform.pathSeparator}android',
    ).create(recursive: true);

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.title == 'Android release signing',
    );
    expect(finding.level, FindingLevel.warning);
    expect(finding.detail, contains('cannot be resolved'));
  });

  test('PASS for valid iOS Release signing configuration', () async {
    final project = await _baseProject(tempRoot, 'ios_valid');
    await _writeIosProject(
      project,
      pbxproj: '''
/* Begin XCBuildConfiguration section */
DBG001 /* Debug */ = {
  isa = XCBuildConfiguration;
  buildSettings = {
    CODE_SIGN_STYLE = Automatic;
    DEVELOPMENT_TEAM = TEAMID1234;
  };
  name = Debug;
};
REL001 /* Release */ = {
  isa = XCBuildConfiguration;
  buildSettings = {
    CODE_SIGN_STYLE = Automatic;
    DEVELOPMENT_TEAM = TEAMID1234;
    CODE_SIGN_ENTITLEMENTS = Runner/Runner.entitlements;
  };
  name = Release;
};
/* End XCBuildConfiguration section */
''',
      scheme: '''
<?xml version="1.0" encoding="UTF-8"?>
<Scheme>
  <LaunchAction buildConfiguration="Debug" />
  <ProfileAction buildConfiguration="Release" />
  <ArchiveAction buildConfiguration="Release" />
</Scheme>
''',
      entitlements: '''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>aps-environment</key>
  <string>production</string>
</dict>
</plist>
''',
    );

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where(
        (f) =>
            f.title == 'iOS release signing' && f.level == FindingLevel.passed,
      ),
      isNotEmpty,
    );
    expect(
      report.findings.where(
        (f) =>
            f.title == 'iOS push entitlements' &&
            f.level == FindingLevel.passed,
      ),
      isNotEmpty,
    );

    final blob = '${report.toConsole()}\n${report.toMarkdown()}';
    expect(blob, isNot(contains('TEAMID1234')));
  });

  test('WARNING when iOS signing settings are unresolved', () async {
    final project = await _baseProject(tempRoot, 'ios_unresolved');
    await _writeIosProject(
      project,
      pbxproj: '''
REL001 /* Release */ = {
  isa = XCBuildConfiguration;
  buildSettings = {
    PRODUCT_BUNDLE_IDENTIFIER = com.example.app;
  };
  name = Release;
};
''',
      scheme: '''
<?xml version="1.0" encoding="UTF-8"?>
<Scheme>
  <ArchiveAction buildConfiguration="Debug" />
</Scheme>
''',
    );

    final report = await ReleaseDoctor().check(project);
    final signing = report.findings.singleWhere(
      (f) => f.title == 'iOS release signing',
    );
    expect(signing.level, FindingLevel.warning);
    expect(signing.detail.toLowerCase(), contains('could not be resolved'));

    final scheme = report.findings.singleWhere(
      (f) => f.title == 'iOS Release scheme',
    );
    expect(scheme.level, FindingLevel.warning);
    expect(scheme.detail, contains('Debug'));

    final blob = '${report.toConsole()}\n${report.toMarkdown()}';
    expect(blob, isNot(contains('TEAMID')));
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

Future<void> _writeIosProject(
  Directory project, {
  required String pbxproj,
  required String scheme,
  String? entitlements,
}) async {
  final xcodeproj = Directory(
    '${project.path}${Platform.pathSeparator}ios${Platform.pathSeparator}Runner.xcodeproj',
  );
  final schemes = Directory(
    '${xcodeproj.path}${Platform.pathSeparator}xcshareddata${Platform.pathSeparator}xcschemes',
  );
  final runner = Directory(
    '${project.path}${Platform.pathSeparator}ios${Platform.pathSeparator}Runner',
  );
  await schemes.create(recursive: true);
  await runner.create(recursive: true);
  await File(
    '${xcodeproj.path}${Platform.pathSeparator}project.pbxproj',
  ).writeAsString(pbxproj);
  await File(
    '${schemes.path}${Platform.pathSeparator}Runner.xcscheme',
  ).writeAsString(scheme);
  if (entitlements != null) {
    await File(
      '${runner.path}${Platform.pathSeparator}Runner.entitlements',
    ).writeAsString(entitlements);
  }
}
