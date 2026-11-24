import 'dart:io';

import 'package:flutter_release_doctor/flutter_release_doctor.dart';
import 'package:test/test.dart';

void main() {
  late Directory tempRoot;

  setUp(() async {
    tempRoot = await Directory.systemTemp.createTemp('release_doctor_cicd_');
  });

  tearDown(() async {
    if (await tempRoot.exists()) {
      await tempRoot.delete(recursive: true);
    }
  });

  test('PASS for valid Android release pipeline', () async {
    final project = await _baseProject(tempRoot, 'android_pipeline');
    await Directory(
      '${project.path}${Platform.pathSeparator}android',
    ).create(recursive: true);
    await _writeWorkflow(project, 'release-android.yml', '''
name: Release Android
on:
  workflow_dispatch:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: flutter pub get
      - run: flutter analyze
      - run: flutter test
      - name: Build
        env:
          KEYSTORE_PASSWORD: \${{ secrets.KEYSTORE_PASSWORD }}
        run: flutter build appbundle --release
''');

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where(
        (f) =>
            f.title == 'CI Flutter validation' &&
            f.level == FindingLevel.passed,
      ),
      isNotEmpty,
    );
    expect(
      report.findings.where(
        (f) =>
            f.title == 'CI Android release build' &&
            f.level == FindingLevel.passed,
      ),
      isNotEmpty,
    );
    expect(
      report.findings.where(
        (f) =>
            f.title == 'CI release trigger' && f.level == FindingLevel.passed,
      ),
      isNotEmpty,
    );
    expect(
      report.findings.where((f) => f.title == 'CI Android signing secrets'),
      isEmpty,
    );
  });

  test('PASS for valid iOS release pipeline', () async {
    final project = await _baseProject(tempRoot, 'ios_pipeline');
    await Directory(
      '${project.path}${Platform.pathSeparator}ios',
    ).create(recursive: true);
    await _writeWorkflow(project, 'release-ios.yml', '''
name: Release iOS
on:
  push:
    tags:
      - 'v*'
jobs:
  build:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      - run: flutter pub get
      - run: flutter test
      - name: Build IPA
        env:
          APP_STORE_CONNECT_API_KEY: \${{ secrets.APP_STORE_CONNECT_API_KEY }}
        run: flutter build ipa
''');

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where(
        (f) =>
            f.title == 'CI iOS release build' && f.level == FindingLevel.passed,
      ),
      isNotEmpty,
    );
    expect(
      report.findings.where(
        (f) =>
            f.title == 'CI Flutter validation' &&
            f.level == FindingLevel.passed,
      ),
      isNotEmpty,
    );
    expect(
      report.findings.where(
        (f) =>
            f.title == 'CI release trigger' && f.level == FindingLevel.passed,
      ),
      isNotEmpty,
    );
  });

  test('WARNING when .github/workflows is missing', () async {
    final project = await _baseProject(tempRoot, 'no_workflows');

    final report = await ReleaseDoctor().check(project);
    final cicd =
        report.findings.where((f) => f.title.startsWith('CI')).toList();
    expect(cicd.length, 1);
    expect(cicd.single.level, FindingLevel.warning);
    expect(cicd.single.title, 'CI/CD workflows');
    expect(cicd.single.detail, contains('.github/workflows'));
  });

  test('WARNING when workflows lack flutter analyze/test validation', () async {
    final project = await _baseProject(tempRoot, 'no_validation');
    await _writeWorkflow(project, 'ci.yml', '''
name: CI
on: workflow_dispatch
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "no flutter validation"
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.title == 'CI Flutter validation',
    );
    expect(finding.level, FindingLevel.warning);
  });

  test('WARNING for unpinned third-party actions', () async {
    final project = await _baseProject(tempRoot, 'unpinned');
    await _writeWorkflow(project, 'ci.yml', '''
name: CI
on: workflow_dispatch
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: some-org/some-action@main
      - run: flutter pub get
      - run: flutter analyze
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.title == 'CI unpinned actions',
    );
    expect(finding.level, FindingLevel.warning);
    expect(finding.detail, contains('some-org/some-action@main'));
  });

  test('ERROR when workflow contains a hard-coded secret', () async {
    final project = await _baseProject(tempRoot, 'hardcoded_secret');
    await Directory(
      '${project.path}${Platform.pathSeparator}android',
    ).create(recursive: true);
    await _writeWorkflow(project, 'release.yml', '''
name: Release
on: workflow_dispatch
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: flutter pub get
      - run: flutter test
      - name: Sign
        run: echo "ok"
        env:
          KEYSTORE_PASSWORD: "super-secret-password-value"
      - run: flutter build apk --release
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.title == 'CI hard-coded secret',
    );
    expect(finding.level, FindingLevel.error);
    expect(report.hasErrors, isTrue);
    expect(finding.detail, isNot(contains('super-secret-password-value')));
    expect(report.toConsole(), isNot(contains('super-secret-password-value')));
  });

  test('WARNING when release build lacks signing secret references', () async {
    final project = await _baseProject(tempRoot, 'missing_signing_secret');
    await Directory(
      '${project.path}${Platform.pathSeparator}android',
    ).create(recursive: true);
    await _writeWorkflow(project, 'release.yml', '''
name: Release
on: workflow_dispatch
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: flutter pub get
      - run: flutter analyze
      - run: flutter build appbundle --release
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.title == 'CI Android signing secrets',
    );
    expect(finding.level, FindingLevel.warning);
    expect(finding.detail, contains('release.yml'));
  });

  test('WARNING for unsafe broad release push trigger', () async {
    final project = await _baseProject(tempRoot, 'broad_trigger');
    await Directory(
      '${project.path}${Platform.pathSeparator}android',
    ).create(recursive: true);
    await _writeWorkflow(project, 'release.yml', '''
name: Release
on:
  push:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: flutter pub get
      - run: flutter test
      - env:
          KEYSTORE_PASSWORD: \${{ secrets.KEYSTORE_PASSWORD }}
        run: flutter build apk --release
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.title == 'CI release trigger' && f.level == FindingLevel.warning,
    );
    expect(finding.detail, contains('release.yml'));
    expect(
      report.findings.where(
        (f) =>
            f.title == 'CI release trigger' && f.level == FindingLevel.passed,
      ),
      isEmpty,
    );
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

Future<void> _writeWorkflow(
  Directory project,
  String name,
  String contents,
) async {
  final dir = Directory(
    '${project.path}${Platform.pathSeparator}.github${Platform.pathSeparator}workflows',
  );
  await dir.create(recursive: true);
  await File('${dir.path}${Platform.pathSeparator}$name')
      .writeAsString(contents);
}
