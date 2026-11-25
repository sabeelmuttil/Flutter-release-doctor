import 'dart:io';

import 'package:flutter_release_doctor/src/finding.dart';

/// GitHub Actions CI/CD release pipeline readiness checks.
///
/// Never makes network calls and never reports secret values—only variable
/// names when necessary.
class CicdCheck {
  CicdCheck({this.ciRequired});

  /// When false, missing workflows are INFO instead of WARNING.
  final bool? ciRequired;

  static final _androidRelease = RegExp(
    r'''flutter\s+build\s+(?:appbundle|apk)\s+[^\n]*--release'''
    r'''|flutter\s+build\s+appbundle'''
    r'''|gradlew?\s+[^\n]*bundleRelease'''
    r'''|\.\/gradlew\s+[^\n]*assembleRelease'''
    r'''|gradlew?\s+[^\n]*assembleRelease''',
    caseSensitive: false,
  );

  static final _iosRelease = RegExp(
    r'''flutter\s+build\s+ipa'''
    r'''|flutter\s+build\s+ios\s+[^\n]*--release'''
    r'''|xcodebuild\s+[^\n]*\barchive\b'''
    r'''|flutter\s+build\s+ios\b''',
    caseSensitive: false,
  );

  static final _signingSecretRef = RegExp(
    r'''secrets\.[A-Z0-9_]*'''
    r'''(?:KEY|PASSWORD|PASS|P12|CERT|SIGN|KEYSTORE|MATCH|ASC|API_KEY|'''
    r'''SERVICE_ACCOUNT|PLAY_STORE|APPSTORE|APPLE|MOBILEPROVISION|'''
    r'''PROVISION|SSH|TOKEN)[A-Z0-9_]*'''
    r'''|\$\{\{\s*secrets\.[A-Z0-9_]+\s*\}\}'''
    r'''|env\.[A-Z0-9_]*(?:KEY|PASSWORD|SIGN|KEYSTORE|CERT|P12|MATCH)[A-Z0-9_]*''',
    caseSensitive: false,
  );

  static final _hardCodedSecret = RegExp(
    r'''(?:password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*["'][^"'\s]{8,}["']'''
    r'''|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'''
    r'''|"private_key"\s*:\s*"-----BEGIN'''
    r'''|"type"\s*:\s*"service_account"'''
    r'''|storePassword\s*[:=]\s*["'][^"']+["']'''
    r'''|keyPassword\s*[:=]\s*["'][^"']+["']''',
    caseSensitive: false,
  );

  static final _usesAction = RegExp(
    r'''uses:\s*([^\s#]+)''',
    caseSensitive: false,
  );

  Future<void> run(Directory project, List<Finding> findings) async {
    final workflowsDir = Directory(_join(project, '.github/workflows'));
    if (!await workflowsDir.exists()) {
      if (ciRequired == false) {
        findings.add(
          const Finding(
            FindingLevel.info,
            'CI/CD workflows',
            'No `.github/workflows` directory was found. store_profile.ci_required=false, so missing CI is informational only.',
            id: 'missing-ci-workflow',
            confidence: FindingConfidence.low,
            source: FindingSource.projectConfig,
            evidenceSummary: 'Profile declares CI is not required',
          ),
        );
      } else {
        findings.add(
          const Finding(
            FindingLevel.warning,
            'CI/CD workflows',
            'No `.github/workflows` directory was found, so release pipeline readiness could not be verified.',
            id: 'missing-ci-workflow',
            confidence: FindingConfidence.medium,
            source: FindingSource.staticAnalysis,
            fix:
                'Add GitHub Actions workflows for Flutter validation and Android/iOS release builds.',
          ),
        );
      }
      return;
    }

    final workflows = await _loadWorkflows(workflowsDir);
    if (workflows.isEmpty) {
      if (ciRequired == false) {
        findings.add(
          const Finding(
            FindingLevel.info,
            'CI/CD workflows',
            '`.github/workflows` exists but no workflow files were found. store_profile.ci_required=false, so this is informational only.',
            id: 'ci-workflows-empty',
            confidence: FindingConfidence.low,
            source: FindingSource.projectConfig,
          ),
        );
      } else {
        findings.add(
          const Finding(
            FindingLevel.warning,
            'CI/CD workflows',
            '`.github/workflows` exists but no `.yml`/`.yaml` workflow files were found.',
            id: 'ci-workflows-empty',
            fix: 'Add at least one GitHub Actions workflow for CI/CD.',
          ),
        );
      }
      return;
    }

    _checkFlutterValidation(workflows, findings);
    await _checkAndroidRelease(project, workflows, findings);
    await _checkIosRelease(project, workflows, findings);
    _checkHardCodedSecrets(workflows, findings);
    _checkUnpinnedActions(workflows, findings);
    _checkReleaseTriggers(workflows, findings);
  }

  Future<List<_Workflow>> _loadWorkflows(Directory dir) async {
    final result = <_Workflow>[];
    await for (final entity in dir.list(followLinks: false, recursive: false)) {
      if (entity is! File) continue;
      final name = entity.uri.pathSegments.last.toLowerCase();
      if (!name.endsWith('.yml') && !name.endsWith('.yaml')) continue;
      result.add(
        _Workflow(
          name: entity.uri.pathSegments.last,
          content: await entity.readAsString(),
        ),
      );
    }
    return result;
  }

  void _checkFlutterValidation(
    List<_Workflow> workflows,
    List<Finding> findings,
  ) {
    final hasPubGet = workflows.any(
      (w) => RegExp(r'flutter\s+pub\s+get', caseSensitive: false)
          .hasMatch(w.content),
    );
    final hasAnalyze = workflows.any(
      (w) => RegExp(r'flutter\s+analyze', caseSensitive: false)
          .hasMatch(w.content),
    );
    final hasTest = workflows.any(
      (w) =>
          RegExp(r'flutter\s+test\b', caseSensitive: false).hasMatch(w.content),
    );

    if (hasPubGet && (hasAnalyze || hasTest)) {
      findings.add(
        Finding(
          FindingLevel.passed,
          'CI Flutter validation',
          'Workflow(s) run `flutter pub get` and '
              '${hasAnalyze && hasTest ? '`flutter analyze` / `flutter test`' : hasAnalyze ? '`flutter analyze`' : '`flutter test`'}.',
          id: 'ci-flutter-validation',
        ),
      );
    } else {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'CI Flutter validation',
          'Workflow files exist but no Flutter validation step combining `flutter pub get` with `flutter analyze` or `flutter test` was found.',
          id: 'ci-flutter-validation',
          fix:
              'Add steps that run `flutter pub get` and `flutter analyze` or `flutter test`.',
        ),
      );
    }
  }

  Future<void> _checkAndroidRelease(
    Directory project,
    List<_Workflow> workflows,
    List<Finding> findings,
  ) async {
    final hasAndroid = await Directory(_join(project, 'android')).exists();
    final androidWorkflows =
        workflows.where((w) => _androidRelease.hasMatch(w.content)).toList();

    if (androidWorkflows.isNotEmpty) {
      findings.add(
        Finding(
          FindingLevel.passed,
          'CI Android release build',
          'Android release build command found in: ${androidWorkflows.map((w) => w.name).join(', ')}.',
          id: 'ci-android-release-build',
        ),
      );
      _checkSigningRefsForReleaseWorkflows(
        androidWorkflows,
        'Android',
        findings,
      );
    } else if (hasAndroid) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'CI Android release build',
          'Android project exists but no Android release build workflow was found.',
          id: 'ci-android-release-build',
          fix:
              'Add a workflow step such as `flutter build appbundle --release` or Gradle `bundleRelease`.',
        ),
      );
    }
  }

  Future<void> _checkIosRelease(
    Directory project,
    List<_Workflow> workflows,
    List<Finding> findings,
  ) async {
    final hasIos = await Directory(_join(project, 'ios')).exists();
    final iosWorkflows =
        workflows.where((w) => _iosRelease.hasMatch(w.content)).toList();

    if (iosWorkflows.isNotEmpty) {
      findings.add(
        Finding(
          FindingLevel.passed,
          'CI iOS release build',
          'iOS release/archive build command found in: ${iosWorkflows.map((w) => w.name).join(', ')}.',
          id: 'ci-ios-release-build',
        ),
      );
      _checkSigningRefsForReleaseWorkflows(iosWorkflows, 'iOS', findings);
    } else if (hasIos) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'CI iOS release build',
          'iOS project exists but no iOS release build workflow was found.',
          id: 'ci-ios-release-build',
          fix:
              'Add a workflow step such as `flutter build ipa` or `xcodebuild archive`.',
        ),
      );
    }
  }

  void _checkSigningRefsForReleaseWorkflows(
    List<_Workflow> releaseWorkflows,
    String platform,
    List<Finding> findings,
  ) {
    for (final workflow in releaseWorkflows) {
      if (_signingSecretRef.hasMatch(workflow.content)) {
        continue;
      }
      // Also accept generic secrets.* near signing keywords without leaking values.
      final hasAnySecrets = RegExp(
        r'''secrets\.[A-Z0-9_]+''',
        caseSensitive: false,
      ).hasMatch(workflow.content);
      final mentionsSigning = RegExp(
        r'keystore|signing|p12|certificate|provision|match|asc_key|play.?store|google.?credentials',
        caseSensitive: false,
      ).hasMatch(workflow.content);

      if (hasAnySecrets && mentionsSigning) continue;

      final signingId = platform == 'Android'
          ? 'ci-android-signing-secrets'
          : 'ci-ios-signing-secrets';
      findings.add(
        Finding(
          FindingLevel.warning,
          'CI $platform signing secrets',
          'Release build found in `${workflow.name}` but no signing-related secret/env reference was detected.',
          id: signingId,
          fix:
              'Reference signing material through GitHub Actions secrets or env (for example KEYSTORE_PASSWORD)—never hard-code values.',
        ),
      );
    }
  }

  void _checkHardCodedSecrets(
    List<_Workflow> workflows,
    List<Finding> findings,
  ) {
    for (final workflow in workflows) {
      // Ignore lines that clearly reference secrets.* placeholders.
      final lines = workflow.content.split('\n');
      for (final line in lines) {
        if (line.contains('secrets.') || line.contains('\${{')) continue;
        if (_hardCodedSecret.hasMatch(line)) {
          findings.add(
            Finding(
              FindingLevel.error,
              'CI hard-coded secret',
              'Workflow `${workflow.name}` appears to contain a hard-coded signing password, private key, API token, or service-account JSON value.',
              id: 'ci-hard-coded-secret',
              fix:
                  'Remove the hard-coded value and load it from GitHub Actions secrets instead. Secret values are not shown in this report.',
            ),
          );
          break;
        }
      }
    }
  }

  void _checkUnpinnedActions(
    List<_Workflow> workflows,
    List<Finding> findings,
  ) {
    final offenders = <String>[];
    for (final workflow in workflows) {
      for (final match in _usesAction.allMatches(workflow.content)) {
        final ref = match.group(1)!.trim();
        if (_isUnpinnedAction(ref)) {
          offenders.add('${workflow.name}: $ref');
        }
      }
    }
    if (offenders.isEmpty) return;
    findings.add(
      Finding(
        FindingLevel.warning,
        'CI unpinned actions',
        'Workflow uses deprecated or unpinned third-party actions: ${offenders.take(5).join('; ')}${offenders.length > 5 ? '…' : ''}.',
        id: 'ci-unpinned-actions',
        fix:
            'Pin actions to a version tag or commit SHA (for example `actions/checkout@v4`). Avoid `@main` / `@master` / unversioned refs.',
      ),
    );
  }

  bool _isUnpinnedAction(String ref) {
    // Local or docker actions are out of scope.
    if (ref.startsWith('./') || ref.startsWith('docker://')) return false;
    final at = ref.lastIndexOf('@');
    if (at < 0) return true;
    final version = ref.substring(at + 1);
    final lower = version.toLowerCase();
    if (lower == 'main' || lower == 'master') return true;
    // Accept v-tags and full git SHAs.
    if (RegExp(r'^v\d+(\.\d+)*$').hasMatch(version)) return false;
    if (RegExp(r'^[0-9a-f]{7,40}$').hasMatch(version)) return false;
    // Branch-like refs without v/sha → unpinned.
    if (RegExp(r'^[A-Za-z][\w./-]*$').hasMatch(version)) return true;
    return false;
  }

  void _checkReleaseTriggers(
    List<_Workflow> workflows,
    List<Finding> findings,
  ) {
    final releaseWorkflows = workflows
        .where(
          (w) =>
              _androidRelease.hasMatch(w.content) ||
              _iosRelease.hasMatch(w.content),
        )
        .toList();
    if (releaseWorkflows.isEmpty) return;

    var anySafe = false;
    for (final workflow in releaseWorkflows) {
      final safe = _hasSafeReleaseTrigger(workflow.content);
      final broad = _hasUnsafeBroadPushTrigger(workflow.content);
      if (safe) {
        anySafe = true;
      }
      if (broad && !safe) {
        findings.add(
          Finding(
            FindingLevel.warning,
            'CI release trigger',
            'Release workflow `${workflow.name}` appears to run on broad push events without branch/tag restriction.',
            id: 'ci-release-trigger',
            fix:
                'Restrict release builds to `workflow_dispatch`, tags, or a protected release branch.',
          ),
        );
      } else if (broad && safe) {
        // Has both safe and broad triggers; still warn about the broad one.
        findings.add(
          Finding(
            FindingLevel.warning,
            'CI release trigger',
            'Release workflow `${workflow.name}` includes an unrestricted push trigger alongside safer triggers.',
            id: 'ci-release-trigger',
            fix:
                'Remove catch-all `push` triggers from release workflows or limit them with branches/tags.',
          ),
        );
      }
    }

    if (anySafe) {
      findings.add(
        const Finding(
          FindingLevel.passed,
          'CI release trigger',
          'A release workflow has a manual (`workflow_dispatch`) or protected tag/release trigger.',
          id: 'ci-release-trigger',
        ),
      );
    }
  }

  bool _hasSafeReleaseTrigger(String content) {
    if (RegExp(r'workflow_dispatch\b').hasMatch(content)) return true;
    if (RegExp(r'''\brelease\s*:''').hasMatch(content)) return true;
    // push: tags: or tags: under on:
    if (RegExp(
      r'''^\s*tags\s*:''',
      multiLine: true,
    ).hasMatch(content)) {
      return true;
    }
    if (RegExp(
      r'''push\s*:\s*\n(?:\s+.+\n)*?\s+tags\s*:''',
    ).hasMatch(content)) {
      return true;
    }
    return false;
  }

  bool _hasUnsafeBroadPushTrigger(String content) {
    // on: [push] or on: push without branches/tags filters nearby.
    if (RegExp(r'''on\s*:\s*\[?[^\]]*push[^\]]*\]?\s*$''', multiLine: true)
        .hasMatch(content)) {
      // Could be `on: [push]` — unsafe if no tags/branches elsewhere in on.
      if (!_hasBranchOrTagRestriction(content)) return true;
    }

    // on:\n  push:\n    # no branches/tags
    final pushBlock = RegExp(
      r'''(?:^|\n)on\s*:\s*\n([\s\S]*?)(?=\n\w|\njobs\s*:|\Z)''',
    ).firstMatch(content);
    if (pushBlock == null) {
      // Flat form: on: push
      if (RegExp(r'''^on\s*:\s*push\s*$''', multiLine: true)
          .hasMatch(content)) {
        return true;
      }
      return false;
    }
    final onSection = pushBlock.group(1)!;
    if (!RegExp(r'''^\s*push\s*:''', multiLine: true).hasMatch(onSection)) {
      return false;
    }
    // If push has branches/tags/paths filters, not "every branch".
    if (RegExp(
      r'''push\s*:\s*\n(?:[^\n]*\n)*?\s+(branches|branches-ignore|tags|tags-ignore)\s*:''',
    ).hasMatch('on:\n$onSection')) {
      return false;
    }
    // push: with empty body or only unrelated keys → broad
    if (RegExp(r'''push\s*:\s*(?:null)?\s*(?:\n|$)''').hasMatch(onSection) ||
        RegExp(r'''push\s*:\s*\n\s*\n''').hasMatch(onSection) ||
        RegExp(r'''^\s*push\s*:\s*$''', multiLine: true).hasMatch(onSection)) {
      // Check if nested filters exist under push
      final nested = RegExp(
        r'''push\s*:\s*\n((?:[ \t]+.+\n?)*)''',
      ).firstMatch(onSection);
      if (nested != null) {
        final body = nested.group(1) ?? '';
        if (body.trim().isEmpty) return true;
        if (RegExp(r'branches|tags').hasMatch(body)) return false;
        // Has other keys but no branch/tag restriction
        return true;
      }
      return true;
    }
    return false;
  }

  bool _hasBranchOrTagRestriction(String content) {
    return RegExp(
      r'''\b(?:branches|tags|branches-ignore|tags-ignore)\s*:''',
    ).hasMatch(content);
  }

  String _join(Directory project, String relative) =>
      '${project.path}${Platform.pathSeparator}${relative.replaceAll('/', Platform.pathSeparator)}';
}

class _Workflow {
  const _Workflow({required this.name, required this.content});

  final String name;
  final String content;
}
