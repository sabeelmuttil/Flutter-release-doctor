import 'dart:io';

/// Opens a URL in the user's default browser.
class BrowserLauncher {
  BrowserLauncher({
    Future<ProcessResult> Function(String executable, List<String> arguments)?
        runProcess,
  }) : _runProcess = runProcess ?? Process.run;

  final Future<ProcessResult> Function(
      String executable, List<String> arguments) _runProcess;

  Future<void> open(Uri url) async {
    if (Platform.isMacOS) {
      final result = await _runProcess('open', [url.toString()]);
      if (result.exitCode != 0) {
        throw StateError('Failed to open browser: ${result.stderr}');
      }
      return;
    }
    if (Platform.isWindows) {
      final result = await _runProcess('powershell', [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        'Start-Process ${psQuote(url.toString())}',
      ]);
      if (result.exitCode != 0) {
        throw StateError('Failed to open browser: ${result.stderr}');
      }
      return;
    }
    if (Platform.isLinux) {
      final result = await _runProcess('xdg-open', [url.toString()]);
      if (result.exitCode != 0) {
        throw StateError('Failed to open browser: ${result.stderr}');
      }
      return;
    }
    throw UnsupportedError('Opening a browser is not supported on this OS.');
  }

  static String psQuote(String value) => "'${value.replaceAll("'", "''")}'";
}
