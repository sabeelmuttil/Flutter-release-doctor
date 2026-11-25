import 'dart:io';

/// Local app-support directories for Flutter Release Doctor (never for tokens).
///
/// Tokens are stored only in OS secure storage. This home directory holds
/// non-secret state such as caches and is created automatically on first run.
class DoctorHome {
  DoctorHome({Directory? homeOverride, String? homePathOverride})
      : _homeOverride = homeOverride,
        _homePathOverride = homePathOverride;

  final Directory? _homeOverride;
  final String? _homePathOverride;

  static const folderName = '.flutter_release_doctor';

  Directory resolveHome() {
    final overrideDir = _homeOverride;
    if (overrideDir != null) return overrideDir;
    final overridePath = _homePathOverride;
    if (overridePath != null && overridePath.trim().isNotEmpty) {
      return Directory(overridePath.trim());
    }
    final envHome = Platform.environment['FLUTTER_RELEASE_DOCTOR_HOME'];
    if (envHome != null && envHome.trim().isNotEmpty) {
      return Directory(envHome.trim());
    }
    final userHome = Platform.environment['HOME'] ??
        Platform.environment['USERPROFILE'] ??
        Directory.systemTemp.path;
    return Directory(
      '$userHome${Platform.pathSeparator}$folderName',
    );
  }

  /// Creates the home directory (and standard subfolders) if missing.
  Future<Directory> ensureCreated() async {
    final home = resolveHome();
    if (!await home.exists()) {
      await home.create(recursive: true);
    }
    final cache = Directory(
      '${home.path}${Platform.pathSeparator}cache',
    );
    if (!await cache.exists()) {
      await cache.create(recursive: true);
    }
    final logs = Directory(
      '${home.path}${Platform.pathSeparator}logs',
    );
    if (!await logs.exists()) {
      await logs.create(recursive: true);
    }
    return home;
  }
}
