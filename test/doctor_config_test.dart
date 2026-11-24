import 'dart:io';

import 'package:flutter_release_doctor/flutter_release_doctor.dart';
import 'package:test/test.dart';

void main() {
  late Directory tempRoot;

  setUp(() async {
    tempRoot = await Directory.systemTemp.createTemp('release_doctor_cfg_');
  });

  tearDown(() async {
    if (await tempRoot.exists()) {
      await tempRoot.delete(recursive: true);
    }
  });

  test('no config preserves current results', () async {
    final project = await _baseProject(tempRoot, 'no_config');
    await _writeManifest(
      project,
      '''
<manifest>
  <uses-permission android:name="android.permission.CAMERA" />
</manifest>
''',
    );

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.any((f) => f.id == 'flutter-project-found'),
      isTrue,
    );
    expect(
      report.findings.any(
        (f) =>
            f.id == 'android-sensitive-permissions' &&
            f.level == FindingLevel.warning,
      ),
      isTrue,
    );
    expect(
      report.findings.any((f) => f.id == 'config-invalid-yaml'),
      isFalse,
    );
    expect(report.toConsole(), contains('[android-sensitive-permissions]'));
    expect(report.toMarkdown(), contains('`android-sensitive-permissions`'));
  });

  test('valid ignore suppresses a normal warning', () async {
    final project = await _baseProject(tempRoot, 'ignore_warning');
    await _writeManifest(
      project,
      '''
<manifest>
  <uses-permission android:name="android.permission.CAMERA" />
</manifest>
''',
    );
    await _writeConfig(project, '''
version: 1
ignore:
  - android-sensitive-permissions
''');

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where((f) => f.id == 'android-sensitive-permissions'),
      isEmpty,
    );
  });

  test('ignored ERROR downgrades to warning', () async {
    final project = await _baseProject(tempRoot, 'ignore_error');
    await File('${project.path}${Platform.pathSeparator}.env.dev')
        .writeAsString('API_BASE_URL=https://api-dev.example.com\n');
    await File('${project.path}${Platform.pathSeparator}.env.prod')
        .writeAsString('API_BASE_URL=https://api-uat.example.com\n');
    await _writeConfig(project, '''
version: 1
ignore:
  - production-api-url
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.id == 'production-api-url',
    );
    expect(finding.level, FindingLevel.warning);
    expect(finding.detail.toLowerCase(), contains('suppressed'));
    expect(report.hasErrors, isFalse);
  });

  test('invalid YAML produces config error', () async {
    final project = await _baseProject(tempRoot, 'bad_yaml');
    await _writeConfig(project, '''
version: 1
ignore: [
  - broken
''');

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.any(
        (f) => f.id == 'config-invalid-yaml' && f.level == FindingLevel.error,
      ),
      isTrue,
    );
    expect(report.hasErrors, isTrue);
  });

  test('invalid severity produces config error', () async {
    final project = await _baseProject(tempRoot, 'bad_severity');
    await _writeConfig(project, '''
version: 1
severity_overrides:
  hard-coded-api-url: critical
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.id == 'config-invalid-severity',
    );
    expect(finding.level, FindingLevel.error);
    expect(finding.detail, contains('critical'));
  });

  test('approved host avoids hard-coded URL warning', () async {
    final project = await _baseProject(tempRoot, 'approved_host');
    final lib = Directory('${project.path}${Platform.pathSeparator}lib');
    await lib.create(recursive: true);
    await File('${lib.path}${Platform.pathSeparator}api.dart').writeAsString('''
class Api {
  static const apiBaseUrl = 'https://api.example.com/v1';
}
''');
    await _writeConfig(project, '''
version: 1
approved_hosts:
  - api.example.com
''');

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where((f) => f.id == 'hard-coded-api-url'),
      isEmpty,
    );
  });

  test('secret-related ERROR cannot be suppressed', () async {
    final project = await _baseProject(tempRoot, 'secret_nosuppress');
    await Directory(
      '${project.path}${Platform.pathSeparator}android',
    ).create(recursive: true);
    final workflows = Directory(
      '${project.path}${Platform.pathSeparator}.github${Platform.pathSeparator}workflows',
    );
    await workflows.create(recursive: true);
    await File('${workflows.path}${Platform.pathSeparator}release.yml')
        .writeAsString('''
name: Release
on: workflow_dispatch
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: flutter pub get
      - run: flutter test
      - env:
          KEYSTORE_PASSWORD: "super-secret-password-value"
        run: flutter build apk --release
''');
    await _writeConfig(project, '''
version: 1
ignore:
  - ci-hard-coded-secret
severity_overrides:
  ci-hard-coded-secret: info
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.id == 'ci-hard-coded-secret',
    );
    expect(finding.level, FindingLevel.error);
    expect(report.toConsole(), isNot(contains('super-secret-password-value')));
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

Future<void> _writeConfig(Directory project, String contents) async {
  await File(
    '${project.path}${Platform.pathSeparator}.release-doctor.yaml',
  ).writeAsString(contents);
}

Future<void> _writeManifest(Directory project, String contents) async {
  final dir = Directory(
    '${project.path}${Platform.pathSeparator}android${Platform.pathSeparator}app${Platform.pathSeparator}src${Platform.pathSeparator}main',
  );
  await dir.create(recursive: true);
  await File('${dir.path}${Platform.pathSeparator}AndroidManifest.xml')
      .writeAsString(contents);
}
