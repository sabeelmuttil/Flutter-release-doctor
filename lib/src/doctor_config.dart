import 'dart:io';

import 'package:flutter_release_doctor/src/finding.dart';
import 'package:yaml/yaml.dart';

class DoctorConfig {
  const DoctorConfig({
    this.version = 1,
    this.ignore = const {},
    this.severityOverrides = const {},
    this.approvedHosts = const {},
  });

  final int version;
  final Set<String> ignore;
  final Map<String, FindingLevel> severityOverrides;
  final Set<String> approvedHosts;

  static const empty = DoctorConfig();
}

class ConfigLoadResult {
  const ConfigLoadResult({required this.config, this.findings = const []});

  final DoctorConfig config;
  final List<Finding> findings;
}

class DoctorConfigLoader {
  static const fileName = '.release-doctor.yaml';

  Future<ConfigLoadResult> load(Directory project) async {
    final file = File(
      '${project.path}${Platform.pathSeparator}$fileName',
    );
    if (!await file.exists()) {
      return const ConfigLoadResult(config: DoctorConfig.empty);
    }

    final raw = await file.readAsString();
    late final dynamic yaml;
    try {
      yaml = loadYaml(raw);
    } catch (e) {
      return ConfigLoadResult(
        config: DoctorConfig.empty,
        findings: [
          Finding(
            FindingLevel.error,
            'Project configuration',
            '`.release-doctor.yaml` is malformed and could not be parsed.',
            id: 'config-invalid-yaml',
            fix:
                'Fix YAML syntax in `.release-doctor.yaml` (see `.release-doctor.example.yaml`). Parser said: ${_safeError(e)}',
          ),
        ],
      );
    }

    if (yaml == null) {
      return const ConfigLoadResult(config: DoctorConfig.empty);
    }
    if (yaml is! YamlMap && yaml is! Map) {
      return ConfigLoadResult(
        config: DoctorConfig.empty,
        findings: [
          const Finding(
            FindingLevel.error,
            'Project configuration',
            '`.release-doctor.yaml` must be a YAML mapping/object at the root.',
            id: 'config-invalid-yaml',
            fix:
                'Use the structure documented in `.release-doctor.example.yaml`.',
          ),
        ],
      );
    }

    final map = _asStringKeyedMap(yaml);
    final configFindings = <Finding>[];

    final ignore = <String>{};
    final ignoreRaw = map['ignore'];
    if (ignoreRaw != null) {
      if (ignoreRaw is! List) {
        configFindings.add(
          const Finding(
            FindingLevel.error,
            'Project configuration',
            '`ignore` must be a list of finding ID strings.',
            id: 'config-invalid-yaml',
            fix: 'Example: ignore: [android-sensitive-permissions]',
          ),
        );
      } else {
        for (final item in ignoreRaw) {
          if (item is String && item.trim().isNotEmpty) {
            ignore.add(item.trim());
          }
        }
      }
    }

    final overrides = <String, FindingLevel>{};
    final overridesRaw = map['severity_overrides'];
    if (overridesRaw != null) {
      if (overridesRaw is! Map) {
        configFindings.add(
          const Finding(
            FindingLevel.error,
            'Project configuration',
            '`severity_overrides` must be a mapping of finding ID to severity.',
            id: 'config-invalid-severity',
            fix: 'Example: severity_overrides: { hard-coded-api-url: error }',
          ),
        );
      } else {
        for (final entry in overridesRaw.entries) {
          final key = entry.key.toString();
          final value = entry.value.toString().trim().toLowerCase();
          final level = _parseSeverity(value);
          if (level == null) {
            configFindings.add(
              Finding(
                FindingLevel.error,
                'Project configuration',
                'Invalid severity `$value` for finding `$key`.',
                id: 'config-invalid-severity',
                fix: 'Use only: error, warning, or info.',
              ),
            );
          } else {
            overrides[key] = level;
          }
        }
      }
    }

    final hosts = <String>{};
    final hostsRaw = map['approved_hosts'];
    if (hostsRaw != null) {
      if (hostsRaw is! List) {
        configFindings.add(
          const Finding(
            FindingLevel.error,
            'Project configuration',
            '`approved_hosts` must be a list of hostnames.',
            id: 'config-invalid-yaml',
            fix: 'Example: approved_hosts: [api.example.com]',
          ),
        );
      } else {
        for (final item in hostsRaw) {
          if (item is String && item.trim().isNotEmpty) {
            hosts.add(item.trim().toLowerCase());
          }
        }
      }
    }

    if (configFindings.isNotEmpty) {
      return ConfigLoadResult(
        config: DoctorConfig.empty,
        findings: configFindings,
      );
    }

    final versionRaw = map['version'];
    final version = versionRaw is int
        ? versionRaw
        : int.tryParse(versionRaw?.toString() ?? '') ?? 1;

    return ConfigLoadResult(
      config: DoctorConfig(
        version: version,
        ignore: ignore,
        severityOverrides: overrides,
        approvedHosts: hosts,
      ),
    );
  }

  /// Applies ignore rules, then severity overrides, to [findings].
  List<Finding> apply(DoctorConfig config, List<Finding> findings) {
    final result = <Finding>[];
    for (final finding in findings) {
      var current = finding;

      if (config.ignore.contains(finding.id)) {
        if (_isNonSuppressible(finding.id)) {
          // Fall through; secret-related findings cannot be suppressed.
        } else if (finding.level == FindingLevel.error) {
          current = finding.copyWith(
            level: FindingLevel.warning,
            detail:
                '${finding.detail} (suppressed by project configuration: ignored `${finding.id}` was downgraded from ERROR to WARNING).',
          );
        } else {
          // Non-error ignored findings are hidden.
          continue;
        }
      }

      final override = config.severityOverrides[current.id];
      if (override != null) {
        if (_isNonSuppressible(current.id) &&
            _rank(override) < _rank(current.level)) {
          // Do not downgrade secret-related findings via overrides.
        } else {
          current = current.copyWith(level: override);
        }
      }

      result.add(current);
    }
    return result;
  }

  bool _isNonSuppressible(String id) => nonSuppressibleFindingIds.contains(id);

  int _rank(FindingLevel level) => switch (level) {
        FindingLevel.error => 3,
        FindingLevel.warning => 2,
        FindingLevel.info => 1,
        FindingLevel.passed => 0,
      };

  FindingLevel? _parseSeverity(String value) {
    return switch (value) {
      'error' => FindingLevel.error,
      'warning' => FindingLevel.warning,
      'info' => FindingLevel.info,
      _ => null,
    };
  }

  Map<String, dynamic> _asStringKeyedMap(dynamic yaml) {
    if (yaml is YamlMap) {
      return {
        for (final e in yaml.entries) e.key.toString(): e.value,
      };
    }
    if (yaml is Map) {
      return {
        for (final e in yaml.entries) e.key.toString(): e.value,
      };
    }
    return {};
  }

  String _safeError(Object e) {
    final text = e.toString().replaceAll(RegExp(r'\s+'), ' ').trim();
    if (text.length <= 160) return text;
    return '${text.substring(0, 160)}…';
  }
}
