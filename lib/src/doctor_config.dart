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

enum StoreBusinessModel {
  physicalGoods,
  digitalGoods,
  subscription,
  mixed,
  unknown,
}

enum StoreAuthentication {
  none,
  emailPassword,
  phoneOtp,
  socialLogin,
  mixed,
  unknown,
}

/// Project policy profile used to avoid irrelevant cross-app findings.
class StoreProfile {
  const StoreProfile({
    this.businessModel = StoreBusinessModel.unknown,
    this.authentication = StoreAuthentication.unknown,
    this.usesLocation,
    this.usesTracking,
    this.hasUserAccounts,
    this.hasUserGeneratedContent,
    this.usesUniversalLinks,
    this.usesAndroidAppLinks,
    this.ciRequired,
    this.reviewerDemoAccount,
  });

  final StoreBusinessModel businessModel;
  final StoreAuthentication authentication;
  final bool? usesLocation;
  final bool? usesTracking;
  final bool? hasUserAccounts;
  final bool? hasUserGeneratedContent;
  final bool? usesUniversalLinks;
  final bool? usesAndroidAppLinks;
  final bool? ciRequired;
  final bool? reviewerDemoAccount;

  bool get isPhysicalGoodsOnly =>
      businessModel == StoreBusinessModel.physicalGoods;

  bool get isDigitalLike =>
      businessModel == StoreBusinessModel.digitalGoods ||
      businessModel == StoreBusinessModel.subscription ||
      businessModel == StoreBusinessModel.mixed;

  bool get isFirstPartyAuthOnly =>
      authentication == StoreAuthentication.emailPassword ||
      authentication == StoreAuthentication.phoneOtp ||
      authentication == StoreAuthentication.none;

  static const empty = StoreProfile();
}

/// Optional identifiers for live store API checks (credentials stay in env/CI).
class StoreIntegrationsConfig {
  const StoreIntegrationsConfig({
    this.googlePlayPackageName,
    this.appStoreBundleId,
  });

  final String? googlePlayPackageName;
  final String? appStoreBundleId;

  static const empty = StoreIntegrationsConfig();
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
    this.storeProfile = StoreProfile.empty,
    this.storeIntegrations = StoreIntegrationsConfig.empty,
  });

  final int version;
  final Set<String> ignore;
  final Map<String, FindingLevel> severityOverrides;
  final Set<String> approvedHosts;
  final TransactionType transactionType;
  final Set<PaymentFlow> paymentFlows;
  final StoreComplianceConfig storeCompliance;
  final StoreProfile storeProfile;
  final StoreIntegrationsConfig storeIntegrations;

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

    var storeProfile = StoreProfile.empty;
    final profileRaw = map['store_profile'];
    if (profileRaw != null) {
      if (profileRaw is! Map && profileRaw is! YamlMap) {
        configFindings.add(
          const Finding(
            FindingLevel.error,
            'Project configuration',
            '`store_profile` must be a mapping/object.',
            id: 'config-invalid-store-profile',
            fix: 'See `.release-doctor.example.yaml` for store_profile keys.',
          ),
        );
      } else {
        final profileMap = _asStringKeyedMap(profileRaw);
        final parsed = _parseStoreProfile(profileMap, configFindings);
        if (parsed != null) {
          storeProfile = parsed;
        }
      }
    }

    var storeIntegrations = StoreIntegrationsConfig.empty;
    final integrationsRaw = map['store_integrations'];
    if (integrationsRaw != null) {
      if (integrationsRaw is! Map && integrationsRaw is! YamlMap) {
        configFindings.add(
          const Finding(
            FindingLevel.error,
            'Project configuration',
            '`store_integrations` must be a mapping/object.',
            id: 'config-invalid-store-integrations',
            fix:
                'See `.release-doctor.example.yaml` for store_integrations keys.',
          ),
        );
      } else {
        final integrationsMap = _asStringKeyedMap(integrationsRaw);
        final parsed = _parseStoreIntegrations(integrationsMap, configFindings);
        if (parsed != null) {
          storeIntegrations = parsed;
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
        storeProfile: storeProfile,
        storeIntegrations: storeIntegrations,
      ),
    );
  }

  StoreIntegrationsConfig? _parseStoreIntegrations(
    Map<String, dynamic> map,
    List<Finding> configFindings,
  ) {
    String? googlePackage;
    final googleRaw = map['google_play'];
    if (googleRaw != null) {
      if (googleRaw is! Map && googleRaw is! YamlMap) {
        configFindings.add(
          const Finding(
            FindingLevel.error,
            'Project configuration',
            '`store_integrations.google_play` must be a mapping/object.',
            id: 'config-invalid-store-integrations',
          ),
        );
        return null;
      }
      final googleMap = _asStringKeyedMap(googleRaw);
      final packageRaw = googleMap['package_name'];
      if (packageRaw != null) {
        final value = packageRaw.toString().trim();
        if (value.isNotEmpty) googlePackage = value;
      }
    }

    String? appleBundle;
    final appleRaw = map['app_store'];
    if (appleRaw != null) {
      if (appleRaw is! Map && appleRaw is! YamlMap) {
        configFindings.add(
          const Finding(
            FindingLevel.error,
            'Project configuration',
            '`store_integrations.app_store` must be a mapping/object.',
            id: 'config-invalid-store-integrations',
          ),
        );
        return null;
      }
      final appleMap = _asStringKeyedMap(appleRaw);
      final bundleRaw = appleMap['bundle_id'];
      if (bundleRaw != null) {
        final value = bundleRaw.toString().trim();
        if (value.isNotEmpty) appleBundle = value;
      }
    }

    return StoreIntegrationsConfig(
      googlePlayPackageName: googlePackage,
      appStoreBundleId: appleBundle,
    );
  }

  StoreProfile? _parseStoreProfile(
    Map<String, dynamic> map,
    List<Finding> configFindings,
  ) {
    var businessModel = StoreBusinessModel.unknown;
    final businessRaw = map['business_model'];
    if (businessRaw != null) {
      final parsed = switch (businessRaw.toString().trim().toLowerCase()) {
        'physical_goods' => StoreBusinessModel.physicalGoods,
        'digital_goods' => StoreBusinessModel.digitalGoods,
        'subscription' => StoreBusinessModel.subscription,
        'mixed' => StoreBusinessModel.mixed,
        'unknown' => StoreBusinessModel.unknown,
        _ => null,
      };
      if (parsed == null) {
        configFindings.add(
          Finding(
            FindingLevel.error,
            'Project configuration',
            'Invalid store_profile.business_model `${businessRaw.toString()}`.',
            id: 'config-invalid-store-profile',
            fix:
                'Use: physical_goods, digital_goods, subscription, mixed, unknown.',
          ),
        );
        return null;
      }
      businessModel = parsed;
    }

    var authentication = StoreAuthentication.unknown;
    final authRaw = map['authentication'];
    if (authRaw != null) {
      final parsed = switch (authRaw.toString().trim().toLowerCase()) {
        'none' => StoreAuthentication.none,
        'email_password' => StoreAuthentication.emailPassword,
        'phone_otp' => StoreAuthentication.phoneOtp,
        'social_login' => StoreAuthentication.socialLogin,
        'mixed' => StoreAuthentication.mixed,
        'unknown' => StoreAuthentication.unknown,
        _ => null,
      };
      if (parsed == null) {
        configFindings.add(
          Finding(
            FindingLevel.error,
            'Project configuration',
            'Invalid store_profile.authentication `${authRaw.toString()}`.',
            id: 'config-invalid-store-profile',
            fix:
                'Use: none, email_password, phone_otp, social_login, mixed, unknown.',
          ),
        );
        return null;
      }
      authentication = parsed;
    }

    bool? parseFlag(String key) {
      final raw = map[key];
      if (raw == null) return null;
      final value = _parseBool(raw);
      if (value == null) {
        configFindings.add(
          Finding(
            FindingLevel.error,
            'Project configuration',
            '`store_profile.$key` must be a boolean.',
            id: 'config-invalid-store-profile',
          ),
        );
      }
      return value;
    }

    final usesLocation = parseFlag('uses_location');
    final usesTracking = parseFlag('uses_tracking');
    final hasUserAccounts = parseFlag('has_user_accounts');
    final hasUgc = parseFlag('has_user_generated_content');
    final usesUniversalLinks = parseFlag('uses_universal_links');
    final usesAndroidAppLinks = parseFlag('uses_android_app_links');
    final ciRequired = parseFlag('ci_required');
    final reviewerDemo = parseFlag('reviewer_demo_account');
    if (configFindings.any((f) => f.id == 'config-invalid-store-profile')) {
      return null;
    }

    return StoreProfile(
      businessModel: businessModel,
      authentication: authentication,
      usesLocation: usesLocation,
      usesTracking: usesTracking,
      hasUserAccounts: hasUserAccounts,
      hasUserGeneratedContent: hasUgc,
      usesUniversalLinks: usesUniversalLinks,
      usesAndroidAppLinks: usesAndroidAppLinks,
      ciRequired: ciRequired,
      reviewerDemoAccount: reviewerDemo,
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
        FindingLevel.error => 4,
        FindingLevel.warning => 3,
        FindingLevel.manualReview => 2,
        FindingLevel.info => 1,
        FindingLevel.passed => 0,
      };

  FindingLevel? _parseSeverity(String value) {
    return switch (value) {
      'error' => FindingLevel.error,
      'warning' => FindingLevel.warning,
      'manual_review' || 'manual-review' => FindingLevel.manualReview,
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
