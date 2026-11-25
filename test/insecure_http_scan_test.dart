import 'dart:io';

import 'package:flutter_release_doctor/flutter_release_doctor.dart';
import 'package:test/test.dart';

void main() {
  late Directory tempRoot;

  setUp(() async {
    tempRoot =
        await Directory.systemTemp.createTemp('release_doctor_http_scan_');
  });

  tearDown(() async {
    if (await tempRoot.exists()) {
      await tempRoot.delete(recursive: true);
    }
  });

  test('Xcode workspace plist with Apple DTD HTTP URL does not warn', () async {
    final project = await _baseProject(tempRoot, 'xcworkspace_dtd');
    final shared = Directory(
      '${project.path}${Platform.pathSeparator}ios'
      '${Platform.pathSeparator}Runner.xcworkspace'
      '${Platform.pathSeparator}xcshareddata',
    );
    await shared.create(recursive: true);
    await File(
      '${shared.path}${Platform.pathSeparator}IDEWorkspaceChecks.plist',
    ).writeAsString('''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>IDEDidComputeMac32BitWarning</key>
  <true/>
</dict>
</plist>
''');

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where((f) => f.id == 'insecure-http'),
      isEmpty,
    );
  });

  test('XML namespace HTTP URL does not warn', () async {
    final project = await _baseProject(tempRoot, 'xml_xmlns');
    final res = Directory(
      '${project.path}${Platform.pathSeparator}android'
      '${Platform.pathSeparator}app'
      '${Platform.pathSeparator}src'
      '${Platform.pathSeparator}main'
      '${Platform.pathSeparator}res'
      '${Platform.pathSeparator}xml',
    );
    await res.create(recursive: true);
    await File('${res.path}${Platform.pathSeparator}network_security.xml')
        .writeAsString('''
<?xml version="1.0" encoding="utf-8"?>
<network-security-config xmlns:android="http://schemas.android.com/apk/res/android">
  <base-config cleartextTrafficPermitted="false" />
</network-security-config>
''');

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where((f) => f.id == 'insecure-http'),
      isEmpty,
    );
  });

  test('real http://api.example.com in Dart warns', () async {
    final project = await _baseProject(tempRoot, 'dart_http');
    final lib = Directory('${project.path}${Platform.pathSeparator}lib');
    await lib.create(recursive: true);
    await File('${lib.path}${Platform.pathSeparator}api.dart').writeAsString('''
const api = 'http://api.example.com/v1/orders';
''');

    final report = await ReleaseDoctor().check(project);
    final http = report.findings.singleWhere((f) => f.id == 'insecure-http');
    expect(http.level, FindingLevel.warning);
    expect(http.file, 'lib/api.dart');
    expect(http.line, isNotNull);
    expect(report.toConsole(), contains('lib/api.dart:'));
  });

  test('real HTTP API URL in .env warns', () async {
    final project = await _baseProject(tempRoot, 'env_http');
    await File('${project.path}${Platform.pathSeparator}.env').writeAsString('''
API_BASE_URL=http://staging.example.com/api
''');

    final report = await ReleaseDoctor().check(project);
    final http = report.findings.singleWhere((f) => f.id == 'insecure-http');
    expect(http.level, FindingLevel.warning);
    expect(http.file, '.env');
    expect(http.line, isNotNull);
  });

  test('localhost and 10.0.2.2 HTTP URLs do not warn', () async {
    final project = await _baseProject(tempRoot, 'local_http');
    final lib = Directory('${project.path}${Platform.pathSeparator}lib');
    await lib.create(recursive: true);
    await File('${lib.path}${Platform.pathSeparator}dev.dart').writeAsString('''
const local = 'http://localhost:8080/api';
const emulator = 'http://10.0.2.2:3000/v1';
''');

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where((f) => f.id == 'insecure-http'),
      isEmpty,
    );
  });

  test('real HTTP URL in plist string value still warns', () async {
    final project = await _baseProject(tempRoot, 'plist_http_value');
    final runner = Directory(
      '${project.path}${Platform.pathSeparator}ios'
      '${Platform.pathSeparator}Runner',
    );
    await runner.create(recursive: true);
    await File('${runner.path}${Platform.pathSeparator}Info.plist')
        .writeAsString('''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>APIBaseURL</key>
  <string>http://api.example.com/v1</string>
</dict>
</plist>
''');

    final report = await ReleaseDoctor().check(project);
    final http = report.findings.singleWhere((f) => f.id == 'insecure-http');
    expect(http.file, contains('Info.plist'));
    expect(http.line, isNotNull);
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
