import 'dart:convert';
import 'dart:io';

import 'package:flutter_release_doctor/flutter_release_doctor.dart';
import 'package:test/test.dart';

void main() {
  late Directory tempRoot;

  setUp(() async {
    tempRoot = await Directory.systemTemp.createTemp('release_doctor_cli_');
  });

  tearDown(() async {
    if (await tempRoot.exists()) {
      await tempRoot.delete(recursive: true);
    }
  });

  test('JSON output is valid and includes required fields', () async {
    final project = await _baseProject(tempRoot, 'json_valid');
    final options = parseCliArguments([
      'check',
      project.path,
      '--format',
      'json',
      '--no-markdown-report',
    ]);
    final stdout = _CaptureSink();
    final code = await runCheckCommand(
      options,
      stdoutSink: stdout,
      stderrSink: _CaptureSink(),
    );

    expect(code, 0);
    final decoded = jsonDecode(stdout.text) as Map<String, dynamic>;
    expect(decoded['schemaVersion'], 1);
    expect(decoded['projectPath'], isA<String>());
    expect(decoded['score'], isA<int>());
    expect(decoded['summary'], isA<Map>());
    expect(decoded['summary']['error'], isA<int>());
    expect(decoded['summary']['warning'], isA<int>());
    expect(decoded['summary']['info'], isA<int>());
    expect(decoded['summary']['passed'], isA<int>());
    expect(decoded['findings'], isA<List>());
    final finding = (decoded['findings'] as List).first as Map<String, dynamic>;
    expect(finding.keys,
        containsAll(['id', 'level', 'title', 'detail', 'fix', 'suppressed']));
    // Pure JSON: no banners before/after.
    expect(stdout.text.trimLeft().startsWith('{'), isTrue);
  });

  test('JSON does not include secret values', () async {
    final project = await _baseProject(tempRoot, 'json_secrets');
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

    final stdout = _CaptureSink();
    final code = await runCheckCommand(
      parseCliArguments([
        'check',
        project.path,
        '--format',
        'json',
        '--no-markdown-report',
        '--fail-on',
        'never',
      ]),
      stdoutSink: stdout,
      stderrSink: _CaptureSink(),
    );

    expect(code, 0);
    expect(stdout.text, isNot(contains('super-secret-password-value')));
    final decoded = jsonDecode(stdout.text) as Map<String, dynamic>;
    expect(
      decoded['findings'].toString(),
      isNot(contains('super-secret-password-value')),
    );
  });

  test('creates --output file and prints a short success line for JSON',
      () async {
    final project = await _baseProject(tempRoot, 'json_output_file');
    final outFile = File(
      '${tempRoot.path}${Platform.pathSeparator}out${Platform.pathSeparator}report.json',
    );
    final stdout = _CaptureSink();
    final code = await runCheckCommand(
      parseCliArguments([
        'check',
        project.path,
        '--format',
        'json',
        '--output',
        outFile.path,
        '--no-markdown-report',
      ]),
      stdoutSink: stdout,
      stderrSink: _CaptureSink(),
    );

    expect(code, 0);
    expect(await outFile.exists(), isTrue);
    expect(jsonDecode(await outFile.readAsString()), isA<Map>());
    expect(stdout.text.trim(), startsWith('Wrote report:'));
    expect(stdout.text.trim().startsWith('{'), isFalse);
  });

  test('--no-markdown-report skips release-doctor-report.md', () async {
    final project = await _baseProject(tempRoot, 'no_md');
    final md = File(
      '${project.path}${Platform.pathSeparator}release-doctor-report.md',
    );
    await runCheckCommand(
      parseCliArguments([
        'check',
        project.path,
        '--no-markdown-report',
      ]),
      stdoutSink: _CaptureSink(),
      stderrSink: _CaptureSink(),
    );
    expect(await md.exists(), isFalse);
  });

  test('--fail-on warning exits 1 when warnings exist', () async {
    final project = await _baseProject(tempRoot, 'fail_warning');
    // Missing CI workflows produces a WARNING.
    final code = await runCheckCommand(
      parseCliArguments([
        'check',
        project.path,
        '--fail-on',
        'warning',
        '--no-markdown-report',
      ]),
      stdoutSink: _CaptureSink(),
      stderrSink: _CaptureSink(),
    );
    expect(code, 1);
  });

  test('--fail-on never exits 0 even with errors', () async {
    final project = await _baseProject(tempRoot, 'fail_never');
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

    final code = await runCheckCommand(
      parseCliArguments([
        'check',
        project.path,
        '--fail-on',
        'never',
        '--no-markdown-report',
      ]),
      stdoutSink: _CaptureSink(),
      stderrSink: _CaptureSink(),
    );
    expect(code, 0);
  });

  test('invalid options exit with usage error code 64', () {
    expect(
      () => parseCliArguments(['check', '--format', 'xml']),
      throwsA(isA<CliUsageException>()),
    );
    expect(
      () => parseCliArguments(['check', '--fail-on', 'sometimes']),
      throwsA(isA<CliUsageException>()),
    );
    expect(
      () => parseCliArguments(['ship-it']),
      throwsA(isA<CliUsageException>()),
    );
  });

  test('refuses to overwrite protected files via --output', () async {
    final project = await _baseProject(tempRoot, 'overwrite_guard');
    final pubspec =
        File('${project.path}${Platform.pathSeparator}pubspec.yaml');
    final stdout = _CaptureSink();
    final stderr = _CaptureSink();
    final code = await runCheckCommand(
      parseCliArguments([
        'check',
        project.path,
        '--format',
        'json',
        '--output',
        pubspec.path,
        '--no-markdown-report',
      ]),
      stdoutSink: stdout,
      stderrSink: stderr,
    );

    expect(code, 64);
    expect(stderr.text, contains('Refusing to overwrite'));
    expect(await pubspec.readAsString(), contains('name: overwrite_guard'));
  });

  test('suppressed flag is true for ignored ERROR downgrades', () async {
    final project = await _baseProject(tempRoot, 'suppressed_flag');
    await File('${project.path}${Platform.pathSeparator}.env.dev')
        .writeAsString('API_BASE_URL=https://api-dev.example.com\n');
    await File('${project.path}${Platform.pathSeparator}.env.prod')
        .writeAsString('API_BASE_URL=https://api-uat.example.com\n');
    await File(
      '${project.path}${Platform.pathSeparator}.release-doctor.yaml',
    ).writeAsString('''
version: 1
ignore:
  - production-api-url
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.id == 'production-api-url',
    );
    expect(finding.suppressed, isTrue);
    expect(finding.level, FindingLevel.warning);
    final json = report.toJson();
    final encoded = (json['findings'] as List)
        .cast<Map<String, dynamic>>()
        .singleWhere((f) => f['id'] == 'production-api-url');
    expect(encoded['suppressed'], isTrue);
  });
}

class _CaptureSink implements IOSink {
  final StringBuffer _buffer = StringBuffer();

  String get text => _buffer.toString();

  @override
  Encoding encoding = utf8;

  @override
  void add(List<int> data) => _buffer.write(utf8.decode(data));

  @override
  void write(Object? object) => _buffer.write(object);

  @override
  void writeAll(Iterable objects, [String separator = '']) =>
      _buffer.writeAll(objects, separator);

  @override
  void writeln([Object? object = '']) => _buffer.writeln(object);

  @override
  void writeCharCode(int charCode) => _buffer.writeCharCode(charCode);

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future addStream(Stream<List<int>> stream) async {
    await for (final chunk in stream) {
      add(chunk);
    }
  }

  @override
  Future flush() async {}

  @override
  Future close() async {}

  @override
  Future get done => Future.value();
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
