import 'dart:io';

import 'package:flutter_release_doctor/flutter_release_doctor.dart';

Future<void> main(List<String> arguments) async {
  final command = arguments.isEmpty ? 'check' : arguments.first;
  final projectPath =
      arguments.length > 1 ? arguments[1] : Directory.current.path;

  if (command == '--help' || command == '-h' || command == 'help') {
    stdout.writeln('''Flutter Release Doctor

Usage:
  flutter_release_doctor check [flutter-project-path]

Runs local release-readiness checks and writes
release-doctor-report.md in the checked project.''');
    return;
  }

  if (command != 'check') {
    stderr.writeln('Unknown command: $command. Run --help for usage.');
    exitCode = 64;
    return;
  }

  final project = Directory(projectPath).absolute;
  final report = await ReleaseDoctor().check(project);
  stdout.writeln(report.toConsole());

  final reportFile = File(
    '${project.path}${Platform.pathSeparator}release-doctor-report.md',
  );
  await reportFile.writeAsString(report.toMarkdown());
  stdout.writeln('\nMarkdown report: ${reportFile.path}');

  if (report.hasErrors) exitCode = 1;
}
