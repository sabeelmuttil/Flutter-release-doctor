import 'dart:io';

import 'package:flutter_release_doctor/src/finding.dart';
import 'package:yaml/yaml.dart';

enum TransactionType {
  digitalGoods,
  subscription,
  physicalGoods,
  externalPayment,
  unknown,
}

/// Honest project declarations of how physical-goods payments work.
///
/// Declarations are never treated as proof of secure transaction handling.
enum PaymentFlow {
  externalGateway,
  cashOnDelivery,
  offlinePayment,
  noInAppPayment,
}

/// Optional store-guideline declarations (risk signals only; not compliance).
class StoreComplianceConfig {
  const StoreComplianceConfig({
    this.privacyPolicyUrl,
    this.accountRequired,
    this.accountDeletionUrl,
    this.demoAccountProvided,
    this.userGeneratedContent,
    this.usesTracking,
  });

  final String? privacyPolicyUrl;
  final bool? accountRequired;
  final String? accountDeletionUrl;
  final bool? demoAccountProvided;
  final bool? userGeneratedContent;
  final bool? usesTracking;

  bool get hasPrivacyPolicyUrl =>
      privacyPolicyUrl != null && privacyPolicyUrl!.trim().isNotEmpty;

  bool get hasAccountDeletionUrl =>
      accountDeletionUrl != null && accountDeletionUrl!.trim().isNotEmpty;

  static const empty = StoreComplianceConfig();
}

class DoctorConfig {
  const DoctorConfig({
    this.version = 1,
    this.ignore = const {},
    this.severityOverrides = const {},
    this.approvedHosts = const {},
    this.transactionType = TransactionType.unknown,
    this.paymentFlows = const {},
    this.storeCompliance = StoreComplianceConfig.empty,
  });

  final int version;
  final Set<String> ignore;
  final Map<String, FindingLevel> severityOverrides;
  final Set<String> approvedHosts;
  final TransactionType transactionType;
  final Set<PaymentFlow> paymentFlows;
  final StoreComplianceConfig storeCompliance;

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

    var transactionType = TransactionType.unknown;
    final transactionRaw = map['transaction_type'];
    if (transactionRaw != null) {
      final parsed = _parseTransactionType(transactionRaw.toString());
      if (parsed == null) {
        configFindings.add(
          Finding(
            FindingLevel.error,
            'Project configuration',
            'Invalid transaction_type `${transactionRaw.toString()}`.',
            id: 'config-invalid-transaction-type',
            fix:
                'Use one of: digital_goods, subscription, physical_goods, external_payment, unknown.',
          ),
        );
      } else {
        transactionType = parsed;
      }
    }

    final paymentFlows = <PaymentFlow>{};
    final paymentFlowsRaw = map['payment_flows'];
    if (paymentFlowsRaw != null) {
      if (paymentFlowsRaw is! List) {
        configFindings.add(
          const Finding(
            FindingLevel.error,
            'Project configuration',
            '`payment_flows` must be a list of flow identifiers.',
            id: 'config-invalid-payment-flows',
            fix: 'Example: payment_flows: [external_gateway, cash_on_delivery]',
          ),
        );
      } else {
        for (final item in paymentFlowsRaw) {
          final parsed = _parsePaymentFlow(item.toString());
          if (parsed == null) {
            configFindings.add(
              Finding(
                FindingLevel.error,
                'Project configuration',
                'Invalid payment_flows entry `${item.toString()}`.',
                id: 'config-invalid-payment-flows',
                fix:
                    'Use: external_gateway, cash_on_delivery, offline_payment, no_in_app_payment.',
              ),
            );
          } else {
            paymentFlows.add(parsed);
          }
        }
      }
    }

    var storeCompliance = StoreComplianceConfig.empty;
    final storeRaw = map['store_compliance'];
    if (storeRaw != null) {
      if (storeRaw is! Map && storeRaw is! YamlMap) {
        configFindings.add(
          const Finding(
            FindingLevel.error,
            'Project configuration',
            '`store_compliance` must be a mapping/object.',
            id: 'config-invalid-store-compliance',
            fix:
                'See `.release-doctor.example.yaml` for store_compliance keys.',
          ),
        );
      } else {
        final storeMap = _asStringKeyedMap(storeRaw);
        final parsed = _parseStoreCompliance(storeMap, configFindings);
        if (parsed != null) {
          storeCompliance = parsed;
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
        transactionType: transactionType,
        paymentFlows: paymentFlows,
        storeCompliance: storeCompliance,
      ),
    );
  }

  StoreComplianceConfig? _parseStoreCompliance(
    Map<String, dynamic> map,
    List<Finding> configFindings,
  ) {
    String? privacyPolicyUrl;
    final privacyRaw = map['privacy_policy_url'];
    if (privacyRaw != null) {
      privacyPolicyUrl = privacyRaw.toString().trim();
    }

    bool? accountRequired;
    final accountRaw = map['account_required'];
    if (accountRaw != null) {
      accountRequired = _parseBool(accountRaw);
      if (accountRequired == null) {
        configFindings.add(
          const Finding(
            FindingLevel.error,
            'Project configuration',
            '`store_compliance.account_required` must be a boolean.',
            id: 'config-invalid-store-compliance',
          ),
        );
        return null;
      }
    }

    String? accountDeletionUrl;
    final deletionRaw = map['account_deletion_url'];
    if (deletionRaw != null) {
      accountDeletionUrl = deletionRaw.toString().trim();
    }

    bool? demoAccountProvided;
    final reviewerRaw = map['reviewer_access'];
    if (reviewerRaw != null) {
      if (reviewerRaw is! Map && reviewerRaw is! YamlMap) {
        configFindings.add(
          const Finding(
            FindingLevel.error,
            'Project configuration',
            '`store_compliance.reviewer_access` must be a mapping.',
            id: 'config-invalid-store-compliance',
          ),
        );
        return null;
      }
      final reviewerMap = _asStringKeyedMap(reviewerRaw);
      final demoRaw = reviewerMap['demo_account_provided'];
      if (demoRaw != null) {
        demoAccountProvided = _parseBool(demoRaw);
        if (demoAccountProvided == null) {
          configFindings.add(
            const Finding(
              FindingLevel.error,
              'Project configuration',
              '`store_compliance.reviewer_access.demo_account_provided` must be a boolean.',
              id: 'config-invalid-store-compliance',
            ),
          );
          return null;
        }
      }
    }

    bool? userGeneratedContent;
    final ugcRaw = map['user_generated_content'];
    if (ugcRaw != null) {
      userGeneratedContent = _parseBool(ugcRaw);
      if (userGeneratedContent == null) {
        configFindings.add(
          const Finding(
            FindingLevel.error,
            'Project configuration',
            '`store_compliance.user_generated_content` must be a boolean.',
            id: 'config-invalid-store-compliance',
          ),
        );
        return null;
      }
    }

    bool? usesTracking;
    final trackingRaw = map['uses_tracking'];
    if (trackingRaw != null) {
      usesTracking = _parseBool(trackingRaw);
      if (usesTracking == null) {
        configFindings.add(
          const Finding(
            FindingLevel.error,
            'Project configuration',
            '`store_compliance.uses_tracking` must be a boolean.',
            id: 'config-invalid-store-compliance',
          ),
        );
        return null;
      }
    }

    return StoreComplianceConfig(
      privacyPolicyUrl: privacyPolicyUrl,
      accountRequired: accountRequired,
      accountDeletionUrl: accountDeletionUrl,
      demoAccountProvided: demoAccountProvided,
      userGeneratedContent: userGeneratedContent,
      usesTracking: usesTracking,
    );
  }

  bool? _parseBool(dynamic value) {
    if (value is bool) return value;
    final text = value.toString().trim().toLowerCase();
    if (text == 'true') return true;
    if (text == 'false') return false;
    return null;
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
            suppressed: true,
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

  TransactionType? _parseTransactionType(String value) {
    return switch (value.trim().toLowerCase()) {
      'digital_goods' => TransactionType.digitalGoods,
      'subscription' => TransactionType.subscription,
      'physical_goods' => TransactionType.physicalGoods,
      'external_payment' => TransactionType.externalPayment,
      'unknown' => TransactionType.unknown,
      _ => null,
    };
  }

  PaymentFlow? _parsePaymentFlow(String value) {
    return switch (value.trim().toLowerCase()) {
      'external_gateway' => PaymentFlow.externalGateway,
      'cash_on_delivery' => PaymentFlow.cashOnDelivery,
      'offline_payment' => PaymentFlow.offlinePayment,
      'no_in_app_payment' => PaymentFlow.noInAppPayment,
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
