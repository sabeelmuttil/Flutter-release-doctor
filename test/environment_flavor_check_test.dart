import 'dart:io';

import 'package:flutter_release_doctor/flutter_release_doctor.dart';
import 'package:test/test.dart';

void main() {
  late Directory tempRoot;

  setUp(() async {
    tempRoot = await Directory.systemTemp.createTemp('release_doctor_env_');
  });

  tearDown(() async {
    if (await tempRoot.exists()) {
      await tempRoot.delete(recursive: true);
    }
  });

  test('ERROR when production API URL points at UAT/staging/dev', () async {
    final project = await _baseProject(tempRoot, 'prod_uat');
    await _writeEnv(project, '.env.dev', 'https://api-dev.example.com');
    await _writeEnv(project, '.env.prod', 'https://api-uat.example.com');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.title == 'Production API URL',
    );

    expect(finding.level, FindingLevel.error);
    expect(finding.detail, contains('.env.prod'));
    expect(finding.detail, contains('api-uat.example.com'));
    expect(finding.fix, isNotNull);
    expect(report.hasErrors, isTrue);
  });

  test('WARNING when multiple environment files share the same API URL',
      () async {
    final project = await _baseProject(tempRoot, 'dup_urls');
    await _writeEnv(project, '.env.dev', 'https://api.example.com');
    await _writeEnv(project, '.env.staging', 'https://api.example.com');
    await _writeEnv(project, '.env.prod', 'https://api.example.com');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.title == 'Duplicate environment API URL',
    );

    expect(finding.level, FindingLevel.warning);
    expect(finding.detail, contains('.env.dev'));
    expect(finding.detail, contains('.env.prod'));
    expect(finding.detail, contains('api.example.com'));
  });

  test('WARNING when environment files exist but production file is missing',
      () async {
    final project = await _baseProject(tempRoot, 'missing_prod');
    await _writeEnv(project, '.env.dev', 'https://api-dev.example.com');
    await _writeEnv(project, '.env.uat', 'https://api-uat.example.com');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.title == 'Production environment file',
    );

    expect(finding.level, FindingLevel.warning);
    expect(finding.detail, contains('.env.dev'));
    expect(finding.detail, contains('.env.prod'));
    expect(
      report.findings.where((f) => f.title == 'Environment files'),
      isEmpty,
    );
  });

  test('WARNING when lib/ hard-codes a non-local API URL', () async {
    final project = await _baseProject(tempRoot, 'hardcoded_url');
    await _writeEnv(project, '.env.dev', 'https://api-dev.example.com');
    await _writeEnv(project, '.env.prod', 'https://api.example.com');

    final lib = Directory('${project.path}${Platform.pathSeparator}lib');
    await lib.create(recursive: true);
    await File('${lib.path}${Platform.pathSeparator}api_client.dart')
        .writeAsString('''
class ApiClient {
  static const apiBaseUrl = 'https://api.example.com/v1';
}
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.title == 'Hard-coded API URL',
    );

    expect(finding.level, FindingLevel.warning);
    expect(finding.detail, contains('api_client.dart'));
    expect(finding.detail, contains('api.example.com'));
    expect(finding.detail.toLowerCase(), isNot(contains('password')));
  });

  test('PASS for a valid multi-environment setup', () async {
    final project = await _baseProject(tempRoot, 'valid_envs');
    await _writeEnv(project, '.env.dev', 'https://api-dev.example.com');
    await _writeEnv(project, '.env.uat', 'https://api-uat.example.com');
    await _writeEnv(project, '.env.staging', 'https://api-staging.example.com');
    await _writeEnv(project, '.env.prod', 'https://api.example.com');

    final androidApp = Directory(
      '${project.path}${Platform.pathSeparator}android${Platform.pathSeparator}app',
    );
    await androidApp.create(recursive: true);
    await File('${androidApp.path}${Platform.pathSeparator}build.gradle')
        .writeAsString('''
android {
    productFlavors {
        dev {
            applicationIdSuffix ".dev"
        }
        uat {
            applicationIdSuffix ".uat"
        }
        prod {
            applicationIdSuffix ""
        }
    }
}
''');

    final report = await ReleaseDoctor().check(project);

    expect(
      report.findings.where(
        (f) => f.title == 'Environment files' && f.level == FindingLevel.passed,
      ),
      isNotEmpty,
    );
    expect(
      report.findings.where(
        (f) =>
            f.title == 'Android product flavors' &&
            f.level == FindingLevel.passed,
      ),
      isNotEmpty,
    );
    expect(
      report.findings.where((f) => f.title == 'Production API URL'),
      isEmpty,
    );
    expect(
      report.findings.where((f) => f.title == 'Duplicate environment API URL'),
      isEmpty,
    );
  });

  test('does not expose secret values from env files in findings', () async {
    final project = await _baseProject(tempRoot, 'secrets');
    await File('${project.path}${Platform.pathSeparator}.env.prod')
        .writeAsString('''
API_BASE_URL=https://api.example.com
API_KEY=super_secret_token_value_should_not_leak
PASSWORD=another-secret-password-value
''');
    await _writeEnv(project, '.env.dev', 'https://api-dev.example.com');

    final report = await ReleaseDoctor().check(project);
    final blob = [
      ...report.findings.map((f) => '${f.detail} ${f.fix ?? ''}'),
      report.toConsole(),
      report.toMarkdown(),
    ].join('\n');

    expect(blob, isNot(contains('super_secret_token_value_should_not_leak')));
    expect(blob, isNot(contains('another-secret-password-value')));
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

Future<void> _writeEnv(Directory project, String name, String apiUrl) async {
  await File('${project.path}${Platform.pathSeparator}$name').writeAsString('''
API_BASE_URL=$apiUrl
# intentionally include a secret that must never appear in reports
API_KEY=should_never_appear_in_report_abcdef
''');
}
