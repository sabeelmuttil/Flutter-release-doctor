import 'dart:convert';
import 'dart:io';

/// OS secure storage for OAuth tokens (Keychain / Credential Manager / Secret Service).
///
/// Never writes tokens into the scanned Flutter project, `.release-doctor.yaml`,
/// reports, or plain-text config files.
abstract class SecureTokenStore {
  Future<void> write(String key, String value);

  Future<String?> read(String key);

  Future<void> delete(String key);

  Future<bool> contains(String key) async {
    final value = await read(key);
    return value != null && value.isNotEmpty;
  }
}

/// In-memory store for tests.
class MemorySecureTokenStore extends SecureTokenStore {
  final Map<String, String> _values = {};

  Map<String, String> get snapshot => Map.unmodifiable(_values);

  @override
  Future<void> write(String key, String value) async {
    _values[key] = value;
  }

  @override
  Future<String?> read(String key) async => _values[key];

  @override
  Future<void> delete(String key) async {
    _values.remove(key);
  }
}

/// Platform-backed secure store.
class PlatformSecureTokenStore extends SecureTokenStore {
  PlatformSecureTokenStore({
    this.serviceName = 'flutter_release_doctor',
    Future<ProcessResult> Function(String executable, List<String> arguments)?
        runProcess,
  }) : _runProcess = runProcess ?? Process.run;

  final String serviceName;
  final Future<ProcessResult> Function(
      String executable, List<String> arguments) _runProcess;

  @override
  Future<void> write(String key, String value) async {
    if (Platform.isMacOS) {
      await _macWrite(key, value);
      return;
    }
    if (Platform.isLinux) {
      await _linuxWrite(key, value);
      return;
    }
    if (Platform.isWindows) {
      await _windowsWrite(key, value);
      return;
    }
    throw UnsupportedError(
      'Secure token storage is not supported on this platform.',
    );
  }

  @override
  Future<String?> read(String key) async {
    if (Platform.isMacOS) return _macRead(key);
    if (Platform.isLinux) return _linuxRead(key);
    if (Platform.isWindows) return _windowsRead(key);
    throw UnsupportedError(
      'Secure token storage is not supported on this platform.',
    );
  }

  @override
  Future<void> delete(String key) async {
    if (Platform.isMacOS) {
      await _macDelete(key);
      return;
    }
    if (Platform.isLinux) {
      await _linuxDelete(key);
      return;
    }
    if (Platform.isWindows) {
      await _windowsDelete(key);
      return;
    }
    throw UnsupportedError(
      'Secure token storage is not supported on this platform.',
    );
  }

  Future<void> _macWrite(String key, String value) async {
    // Delete existing item first so -U update is reliable.
    await _macDelete(key);
    final result = await _runProcess('security', [
      'add-generic-password',
      '-a',
      serviceName,
      '-s',
      key,
      '-w',
      value,
      '-U',
    ]);
    if (result.exitCode != 0) {
      throw StateError(
        'Failed to store token in macOS Keychain: ${_trim(result.stderr)}',
      );
    }
  }

  Future<String?> _macRead(String key) async {
    final result = await _runProcess('security', [
      'find-generic-password',
      '-a',
      serviceName,
      '-s',
      key,
      '-w',
    ]);
    if (result.exitCode != 0) return null;
    final text = result.stdout.toString().trim();
    return text.isEmpty ? null : text;
  }

  Future<void> _macDelete(String key) async {
    await _runProcess('security', [
      'delete-generic-password',
      '-a',
      serviceName,
      '-s',
      key,
    ]);
  }

  Future<void> _linuxWrite(String key, String value) async {
    final result = await _runProcess('bash', [
      '-lc',
      "printf %s ${shellSingleQuote(value)} | "
          "secret-tool store --label=${shellSingleQuote('Flutter Release Doctor')} "
          "service ${shellSingleQuote(serviceName)} account ${shellSingleQuote(key)}",
    ]);
    if (result.exitCode != 0) {
      throw StateError(
        'Failed to store token in Linux Secret Service '
        '(is secret-tool / gnome-keyring available?): ${_trim(result.stderr)}',
      );
    }
  }

  Future<String?> _linuxRead(String key) async {
    final result = await _runProcess('secret-tool', [
      'lookup',
      'service',
      serviceName,
      'account',
      key,
    ]);
    if (result.exitCode != 0) return null;
    final text = result.stdout.toString();
    return text.isEmpty ? null : text;
  }

  Future<void> _linuxDelete(String key) async {
    await _runProcess('secret-tool', [
      'clear',
      'service',
      serviceName,
      'account',
      key,
    ]);
  }

  Future<void> _windowsWrite(String key, String value) async {
    final b64 = base64.encode(utf8.encode(value));
    final script = '''
\$ErrorActionPreference = 'Stop'
\$target = ${psQuote('$serviceName/$key')}
\$user = 'oauth'
\$pass = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(${psQuote(b64)}))
cmdkey /delete:\$target 2>\$null | Out-Null
\$result = cmdkey /generic:\$target /user:\$user /pass:\$pass
if (\$LASTEXITCODE -ne 0) { throw "cmdkey failed: \$result" }
# Also mirror into a DPAPI-protected user file under LocalAppData as retrieveable backup
# because cmdkey cannot read secrets back. Prefer Credential Manager via .NET:
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class FrdCred {
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  public struct CREDENTIAL {
    public UInt32 Flags; public UInt32 Type; public string TargetName; public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten; public UInt32 CredentialBlobSize;
    public IntPtr CredentialBlob; public UInt32 Persist; public UInt32 AttributeCount; public IntPtr Attributes;
    public string TargetAlias; public string UserName;
  }
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool CredWrite([In] ref CREDENTIAL userCredential, [In] UInt32 flags);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool CredDelete(string target, UInt32 type, UInt32 flags);
}
"@
[void][FrdCred]::CredDelete(\$target, 1, 0)
\$bytes = [Text.Encoding]::UTF8.GetBytes(\$pass)
\$handle = [Runtime.InteropServices.Marshal]::AllocHGlobal(\$bytes.Length)
[Runtime.InteropServices.Marshal]::Copy(\$bytes, 0, \$handle, \$bytes.Length)
\$cred = New-Object FrdCred+CREDENTIAL
\$cred.Type = 1
\$cred.TargetName = \$target
\$cred.UserName = \$user
\$cred.CredentialBlobSize = \$bytes.Length
\$cred.CredentialBlob = \$handle
\$cred.Persist = 1
\$ok = [FrdCred]::CredWrite([ref]\$cred, 0)
[Runtime.InteropServices.Marshal]::FreeHGlobal(\$handle)
if (-not \$ok) { throw "CredWrite failed" }
''';
    final result = await _runProcess('powershell', [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      script,
    ]);
    if (result.exitCode != 0) {
      throw StateError(
        'Failed to store token in Windows Credential Manager: ${_trim(result.stderr)}',
      );
    }
  }

  Future<String?> _windowsRead(String key) async {
    final script = '''
\$ErrorActionPreference = 'Stop'
\$target = ${psQuote('$serviceName/$key')}
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class FrdCredRead {
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  public struct CREDENTIAL {
    public UInt32 Flags; public UInt32 Type; public string TargetName; public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten; public UInt32 CredentialBlobSize;
    public IntPtr CredentialBlob; public UInt32 Persist; public UInt32 AttributeCount; public IntPtr Attributes;
    public string TargetAlias; public string UserName;
  }
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool CredRead(string target, UInt32 type, UInt32 reservedFlag, out IntPtr credentialPtr);
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool CredFree([In] IntPtr buffer);
}
"@
\$ptr = [IntPtr]::Zero
if (-not [FrdCredRead]::CredRead(\$target, 1, 0, [ref]\$ptr)) { exit 2 }
try {
  \$cred = [Runtime.InteropServices.Marshal]::PtrToStructure(\$ptr, [type][FrdCredRead+CREDENTIAL])
  \$bytes = New-Object byte[] \$cred.CredentialBlobSize
  [Runtime.InteropServices.Marshal]::Copy(\$cred.CredentialBlob, \$bytes, 0, \$cred.CredentialBlobSize)
  [Text.Encoding]::UTF8.GetString(\$bytes)
} finally {
  [FrdCredRead]::CredFree(\$ptr) | Out-Null
}
''';
    final result = await _runProcess('powershell', [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      script,
    ]);
    if (result.exitCode != 0) return null;
    final text = result.stdout.toString();
    if (text.isEmpty) return null;
    // PowerShell may append a trailing newline.
    return text.replaceAll(RegExp(r'\r?\n$'), '');
  }

  Future<void> _windowsDelete(String key) async {
    final target = '$serviceName/$key';
    await _runProcess('cmdkey', ['/delete:$target']);
    final script = '''
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class FrdCredDel {
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool CredDelete(string target, UInt32 type, UInt32 flags);
}
"@
[void][FrdCredDel]::CredDelete(${psQuote(target)}, 1, 0)
''';
    await _runProcess('powershell', [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      script,
    ]);
  }

  static String shellSingleQuote(String value) =>
      "'${value.replaceAll("'", "'\\''")}'";

  static String psQuote(String value) => "'${value.replaceAll("'", "''")}'";

  static String _trim(Object? value) {
    final text = value?.toString().replaceAll(RegExp(r'\s+'), ' ').trim() ?? '';
    if (text.length <= 200) return text;
    return '${text.substring(0, 200)}…';
  }
}
