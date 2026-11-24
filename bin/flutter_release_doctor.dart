import 'dart:io';

import 'package:flutter_release_doctor/flutter_release_doctor.dart';

Future<void> main(List<String> arguments) async {
  try {
    final options = parseCliArguments(arguments);
    exitCode = await runCheckCommand(options);
  } on CliUsageException catch (e) {
    stderr.writeln(e.message);
    stderr.writeln('Run --help for usage.');
    exitCode = 64;
  }
}
