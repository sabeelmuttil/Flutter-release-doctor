import 'dart:convert';
import 'dart:io';

import 'package:flutter_release_doctor/src/auth/auth_commands.dart';
import 'package:flutter_release_doctor/src/release_doctor.dart';

enum OutputFormat { console, markdown, json }

enum FailOn { error, warning, never }

class CliUsageException implements Exception {
  CliUsageException(this.message);
  final String message;

  @override
  String toString() => message;
}

class CliOptions {
  const CliOptions({
    required this.projectPath,
    this.format = OutputFormat.console,
    this.outputPath,
    this.failOn = FailOn.error,
    this.writeMarkdownReport = true,
    this.help = false,
    this.liveStore = LiveStoreOptions.offline,
  });

  final String projectPath;
  final OutputFormat format;
  final String? outputPath;
  final FailOn failOn;
  final bool writeMarkdownReport;
  final bool help;
  final LiveStoreOptions liveStore;
}

const protectedOutputNames = <String>{
  'pubspec.yaml',
  'pubspec.lock',
  'analysis_options.yaml',
  '.release-doctor.yaml',
  '.env',
};

bool isProtectedOutputPath(String path) {
  final name = path.split(RegExp(r'[/\\]')).last;
  if (protectedOutputNames.contains(name)) return true;
  if (name == '.env' || name.startsWith('.env.')) return true;
  return false;
}

/// Top-level CLI entry used by `bin/flutter_release_doctor.dart`.
Future<int> runFlutterReleaseDoctor(
  List<String> arguments, {
  IOSink? stdoutSink,
  IOSink? stderrSink,
  AuthCommands? authCommands,
}) async {
  final out = stdoutSink ?? stdout;
  final err = stderrSink ?? stderr;

  if (arguments.isEmpty ||
      arguments.first == '--help' ||
      arguments.first == '-h' ||
      arguments.first == 'help') {
    out.writeln(cliHelpText());
    return 0;
  }

  final command = arguments.first;
  switch (command) {
    case 'check':
      final options = parseCliArguments(arguments);
      return runCheckCommand(
        options,
        stdoutSink: out,
        stderrSink: err,
      );
    case 'connect':
      final options = parseConnectArguments(arguments);
      return (authCommands ?? AuthCommands()).connectGoogle(
        options,
        stdoutSink: out,
        stderrSink: err,
      );
    case 'auth':
      return runAuthCommand(
        arguments,
        stdoutSink: out,
        stderrSink: err,
        authCommands: authCommands,
      );
    default:
      throw CliUsageException(
        'Unknown command: $command. Run --help for usage.',
      );
  }
}

ConnectGoogleOptions parseConnectArguments(List<String> arguments) {
  if (arguments.length < 2 || arguments[1] != 'google') {
    throw CliUsageException(
      'Usage: flutter_release_doctor connect google [--no-browser] [--oauth-client-file <path>] [--package <id>]',
    );
  }

  var noBrowser = false;
  String? oauthClientFile;
  String? packageName;

  for (var i = 2; i < arguments.length; i++) {
    final arg = arguments[i];
    if (arg == '--no-browser') {
      noBrowser = true;
      continue;
    }
    if (arg == '--oauth-client-file') {
      if (i + 1 >= arguments.length) {
        throw CliUsageException('--oauth-client-file requires a path');
      }
      oauthClientFile = arguments[++i];
      continue;
    }
    if (arg.startsWith('--oauth-client-file=')) {
      oauthClientFile = arg.substring('--oauth-client-file='.length);
      continue;
    }
    if (arg == '--package') {
      if (i + 1 >= arguments.length) {
        throw CliUsageException('--package requires an application id');
      }
      packageName = arguments[++i];
      continue;
    }
    if (arg.startsWith('--package=')) {
      packageName = arg.substring('--package='.length);
      continue;
    }
    if (arg.startsWith('-')) {
      throw CliUsageException('Unknown option: $arg');
    }
    throw CliUsageException('Unexpected argument: $arg');
  }

  return ConnectGoogleOptions(
    noBrowser: noBrowser,
    oauthClientFile: oauthClientFile,
    packageName: packageName,
  );
}

Future<int> runAuthCommand(
  List<String> arguments, {
  IOSink? stdoutSink,
  IOSink? stderrSink,
  AuthCommands? authCommands,
}) async {
  final commands = authCommands ?? AuthCommands();
  if (arguments.length < 2) {
    throw CliUsageException(
      'Usage: flutter_release_doctor auth status|logout google',
    );
  }
  final sub = arguments[1];
  if (sub == 'status') {
    if (arguments.length > 2) {
      throw CliUsageException('Unexpected argument: ${arguments[2]}');
    }
    return commands.authStatus(
      stdoutSink: stdoutSink,
      stderrSink: stderrSink,
    );
  }
  if (sub == 'logout') {
    if (arguments.length < 3 || arguments[2] != 'google') {
      throw CliUsageException(
          'Usage: flutter_release_doctor auth logout google');
    }
    if (arguments.length > 3) {
      throw CliUsageException('Unexpected argument: ${arguments[3]}');
    }
    return commands.authLogoutGoogle(
      stdoutSink: stdoutSink,
      stderrSink: stderrSink,
    );
  }
  throw CliUsageException(
    'Unknown auth command: $sub. Use status or logout google.',
  );
}

CliOptions parseCliArguments(List<String> arguments) {
  if (arguments.isEmpty ||
      arguments.first == '--help' ||
      arguments.first == '-h' ||
      arguments.first == 'help') {
    return CliOptions(projectPath: Directory.current.path, help: true);
  }

  final command = arguments.first;
  if (command != 'check') {
    throw CliUsageException('Unknown command: $command. Run --help for usage.');
  }

  var format = OutputFormat.console;
  String? outputPath;
  var failOn = FailOn.error;
  var writeMarkdownReport = true;
  String? projectPath;
  var online = false;
  var store = StoreTarget.both;
  var storeCheckEnabled = true;

  for (var i = 1; i < arguments.length; i++) {
    final arg = arguments[i];
    if (arg == '--help' || arg == '-h') {
      return CliOptions(projectPath: Directory.current.path, help: true);
    }
    if (arg == '--no-markdown-report') {
      writeMarkdownReport = false;
      continue;
    }
    if (arg == '--online') {
      online = true;
      continue;
    }
    if (arg == '--no-store-check') {
      storeCheckEnabled = false;
      continue;
    }
    if (arg == '--store') {
      if (i + 1 >= arguments.length) {
        throw CliUsageException('--store requires a value: google|apple|both');
      }
      store = _parseStoreTarget(arguments[++i]);
      continue;
    }
    if (arg.startsWith('--store=')) {
      store = _parseStoreTarget(arg.substring('--store='.length));
      continue;
    }
    if (arg == '--format') {
      if (i + 1 >= arguments.length) {
        throw CliUsageException(
            '--format requires a value: console|markdown|json');
      }
      format = _parseFormat(arguments[++i]);
      continue;
    }
    if (arg.startsWith('--format=')) {
      format = _parseFormat(arg.substring('--format='.length));
      continue;
    }
    if (arg == '--output') {
      if (i + 1 >= arguments.length) {
        throw CliUsageException('--output requires a file path');
      }
      outputPath = arguments[++i];
      continue;
    }
    if (arg.startsWith('--output=')) {
      outputPath = arg.substring('--output='.length);
      continue;
    }
    if (arg == '--fail-on') {
      if (i + 1 >= arguments.length) {
        throw CliUsageException(
            '--fail-on requires a value: error|warning|never');
      }
      failOn = _parseFailOn(arguments[++i]);
      continue;
    }
    if (arg.startsWith('--fail-on=')) {
      failOn = _parseFailOn(arg.substring('--fail-on='.length));
      continue;
    }
    if (arg.startsWith('-')) {
      throw CliUsageException('Unknown option: $arg');
    }
    if (projectPath != null) {
      throw CliUsageException('Unexpected argument: $arg');
    }
    projectPath = arg;
  }

  return CliOptions(
    projectPath: projectPath ?? Directory.current.path,
    format: format,
    outputPath: outputPath,
    failOn: failOn,
    writeMarkdownReport: writeMarkdownReport,
    liveStore: LiveStoreOptions(
      online: online,
      store: store,
      enabled: storeCheckEnabled,
    ),
  );
}

OutputFormat _parseFormat(String value) {
  return switch (value) {
    'console' => OutputFormat.console,
    'markdown' => OutputFormat.markdown,
    'json' => OutputFormat.json,
    _ => throw CliUsageException(
        'Invalid --format `$value`. Use console|markdown|json.',
      ),
  };
}

FailOn _parseFailOn(String value) {
  return switch (value) {
    'error' => FailOn.error,
    'warning' => FailOn.warning,
    'never' => FailOn.never,
    _ => throw CliUsageException(
        'Invalid --fail-on `$value`. Use error|warning|never.',
      ),
  };
}

StoreTarget _parseStoreTarget(String value) {
  return switch (value.trim().toLowerCase()) {
    'google' => StoreTarget.google,
    'apple' => StoreTarget.apple,
    'both' => StoreTarget.both,
    _ => throw CliUsageException(
        'Invalid --store `$value`. Use google|apple|both.',
      ),
  };
}

String cliHelpText() => '''Flutter Release Doctor

Usage:
  flutter_release_doctor check [flutter-project-path] [options]
  flutter_release_doctor connect google [options]
  flutter_release_doctor auth status
  flutter_release_doctor auth logout google

Check options:
  --format console|markdown|json   Output format (default: console)
  --output <file-path>             Write the selected format to a file
  --fail-on error|warning|never    Exit policy (default: error)
  --no-markdown-report             Do not write release-doctor-report.md
  --online                         Enable optional live store API checks
  --store google|apple|both        Live store target (default: both)
  --no-store-check                 Skip live store verification even with --online

Connect google options:
  --no-browser                     Print the authorization URL (headless)
  --oauth-client-file <path>       Desktop OAuth client JSON (required unless env set)
  --package <applicationId>        Optional package for Play Console access probe

Defaults:
  - offline only (no network / no login required for check)
  - Google OAuth credentials stay outside the repo (file or env)
  - tokens stored in OS secure storage after connect
  - console output on stdout
  - writes release-doctor-report.md in the scanned project
  - exit 1 when ERROR findings exist

  -h, --help                       Show this help''';

/// Runs the check command. Returns a process exit code.
Future<int> runCheckCommand(
  CliOptions options, {
  IOSink? stdoutSink,
  IOSink? stderrSink,
}) async {
  final out = stdoutSink ?? stdout;
  final err = stderrSink ?? stderr;

  if (options.help) {
    out.writeln(cliHelpText());
    return 0;
  }

  final project = Directory(options.projectPath).absolute;
  final report = await ReleaseDoctor().check(
    project,
    liveStore: options.liveStore,
  );
  final rendered = _render(report, options.format);

  if (options.outputPath != null) {
    final code = await _writeOutput(options.outputPath!, rendered, out, err);
    if (code != 0) return code;
  } else {
    out.writeln(rendered);
  }

  if (options.writeMarkdownReport) {
    final reportFile = File(
      '${project.path}${Platform.pathSeparator}release-doctor-report.md',
    );
    await reportFile.writeAsString(report.toMarkdown());
    // Keep stdout pure for --format json; mention path only for console default.
    if (options.format == OutputFormat.console && options.outputPath == null) {
      out.writeln('\nMarkdown report: ${reportFile.path}');
    }
  }

  return _exitCode(report, options.failOn);
}

String _render(DoctorReport report, OutputFormat format) {
  return switch (format) {
    OutputFormat.console => report.toConsole(),
    OutputFormat.markdown => report.toMarkdown(),
    OutputFormat.json => report.toJsonString(),
  };
}

Future<int> _writeOutput(
  String outputPath,
  String contents,
  IOSink out,
  IOSink err,
) async {
  final file = File(outputPath).absolute;
  if (await file.exists() && isProtectedOutputPath(file.path)) {
    err.writeln(
      'Refusing to overwrite protected file: ${file.path}',
    );
    return 64;
  }

  try {
    final parent = file.parent;
    if (!await parent.exists()) {
      await parent.create(recursive: true);
    }
    await file.writeAsString(contents);
  } catch (e) {
    err.writeln('Failed to write output file: $e');
    return 64;
  }

  out.writeln('Wrote report: ${file.path}');
  return 0;
}

int _exitCode(DoctorReport report, FailOn failOn) {
  return switch (failOn) {
    FailOn.never => 0,
    FailOn.error => report.hasErrors ? 1 : 0,
    FailOn.warning => (report.hasErrors || report.hasWarnings) ? 1 : 0,
  };
}

/// Parses JSON text and returns the decoded map (for tests).
Map<String, dynamic> decodeReportJson(String text) =>
    jsonDecode(text) as Map<String, dynamic>;
