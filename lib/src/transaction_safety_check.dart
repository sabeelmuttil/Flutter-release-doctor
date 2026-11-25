import 'dart:io';

import 'package:flutter_release_doctor/src/doctor_config.dart';
import 'package:flutter_release_doctor/src/evidence.dart';
import 'package:flutter_release_doctor/src/finding.dart';

/// Offline Google Play Billing / transaction-safety analyzer.
///
/// Never prints purchase tokens, API keys, card values, or transaction data.
class TransactionSafetyCheck {
  TransactionSafetyCheck({
    required this.transactionType,
    this.paymentFlows = const {},
  });

  final TransactionType transactionType;
  final Set<PaymentFlow> paymentFlows;

  static final _billingDeps = RegExp(
    r'\b(in_app_purchase(?:_android|_storekit)?|purchases_flutter|flutter_inapp_purchase)\b',
    caseSensitive: false,
  );

  /// Package names that commonly indicate gateway / WebView checkout flows.
  static final _externalPaymentDeps = RegExp(
    r'[a-z0-9_-]*(?:stripe|razorpay|paytm|juspay|cashfree|payu|phonepe|'
    r'paypal|ccavenue|flutterwave|squareup|webview|in_app_webview)[a-z0-9_-]*',
    caseSensitive: false,
  );

  static final _purchaseStream = RegExp(
    r'purchaseUpdatedStream|purchaseStream|InAppPurchase\.instance\.purchaseStream',
    caseSensitive: false,
  );

  static final _completePurchase = RegExp(
    r'\bcompletePurchase\s*\(|acknowledgePurchase(?:Android)?\s*\(|'
    r'\.acknowledge\s*\(',
    caseSensitive: false,
  );

  static final _backendVerify = RegExp(
    r'verifyPurchase|validatePurchase|validateReceipt|verifyReceipt|'
    r'verify_purchase|validate_receipt|purchaseVerification|'
    r'serverVerificationData|verificationData\.serverVerificationData|'
    r'/verify[-_]?purchase|/validate[-_]?receipt|'
    r'verifyWith(?:Backend|Server)|confirmPurchaseOnServer',
    caseSensitive: false,
  );

  static final _purchaseToken = RegExp(
    r'purchase(?:ID|Id|Token)|verificationData|serverVerificationData|'
    r'billingClientPurchase\.purchaseToken',
    caseSensitive: false,
  );

  static final _entitlementGrant = RegExp(
    r'grantEntitlement|unlockPremium|unlockPro|setPremium\s*\(|'
    r'isPremium\s*=\s*true|premium\s*=\s*true|entitleUser|'
    r'activateSubscription|enableProFeatures|deliverDigitalContent|'
    r'grantAccess|unlockFeature',
    caseSensitive: false,
  );

  static final _duplicateToken = RegExp(
    r'processedPurchase|seenPurchase|handledPurchase|purchaseIds?\.(?:contains|add)|'
    r'duplicatePurchase|alreadyProcessed|processedTokens',
    caseSensitive: false,
  );

  static final _restorePurchases = RegExp(
    r'restorePurchases\s*\(|restorePurchases',
    caseSensitive: false,
  );

  static final _pendingState = RegExp(
    r'PurchaseStatus\.pending|PurchaseState\.pending|status\s*==\s*PurchaseStatus\.pending',
    caseSensitive: false,
  );

  static final _canceledState = RegExp(
    r'PurchaseStatus\.canceled|PurchaseStatus\.cancelled|'
    r'PurchaseState\.canceled|PurchaseState\.cancelled',
    caseSensitive: false,
  );

  static final _restoredState = RegExp(
    r'PurchaseStatus\.restored|PurchaseState\.restored',
    caseSensitive: false,
  );

  static final _externalPaymentUsage = RegExp(
    r'Razorpay\s*\(|razorpay\.open|Stripe\.\w+|\bStripe\b|Checkout\.session|'
    r'openCheckout|\bPaytm\b|\bJuspay\b|\bCashfree\b|Flutterwave|PayPal',
    caseSensitive: false,
  );

  /// Common Flutter payment symbols / method names used by food & commerce apps.
  static final _paymentFlowSymbols = RegExp(
    r'\b(?:payment|checkout|payNow|makePayment|startTransaction|'
    r'initiateTransaction|createPayment|orderPayment)\b',
    caseSensitive: false,
  );

  /// URL / API path fragments that suggest a payment or checkout endpoint.
  static final _paymentApiPath = RegExp(
    r'''['"`][^'"`]*(?:/?payment|/?checkout|/?transaction|/?gateway|order[-_]?payment)[^'"`]*['"`]''',
    caseSensitive: false,
  );

  static final _cashOnDelivery = RegExp(
    r'\bCOD\b|\bcashOnDelivery\b|\bcash_on_delivery\b',
    caseSensitive: false,
  );

  Future<void> run(Directory project, List<Finding> findings) async {
    final signals = await _scan(project);
    _emitTransactionTypeSummary(findings);

    switch (transactionType) {
      case TransactionType.digitalGoods:
      case TransactionType.subscription:
        _analyzeDigital(signals, findings);
      case TransactionType.physicalGoods:
        _analyzePhysical(signals, findings);
      case TransactionType.externalPayment:
        _analyzeExternal(signals, findings);
      case TransactionType.unknown:
        _analyzeUnknown(signals, findings);
    }
  }

  void _emitTransactionTypeSummary(List<Finding> findings) {
    final label = _typeLabel();
    final configured = transactionType != TransactionType.unknown;
    findings.add(
      Finding(
        configured ? FindingLevel.passed : FindingLevel.info,
        'Transaction type',
        'Transaction type configured as $label.',
        id: 'transaction-type',
      ),
    );
  }

  void _analyzeDigital(_Signals s, List<Finding> findings) {
    if (!s.hasBillingDependency && !s.hasPurchaseStream) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'Digital purchase integration',
          'transaction_type is `${_typeLabel()}` but no Google Play Billing / in_app_purchase integration was detected.',
          id: 'transaction-billing-missing',
          fix:
              'Add in_app_purchase (or equivalent) and implement a secure purchase flow with backend verification.',
        ),
      );
      return;
    }

    if (s.hasBillingDependency) {
      findings.add(
        Finding(
          FindingLevel.passed,
          'Billing dependency',
          'Google Play Billing / in-app purchase dependency detected.',
          id: 'transaction-billing-dependency',
          file: s.billingDepFile,
          line: s.billingDepLine,
        ),
      );
    }

    if (s.hasPurchaseStream) {
      findings.add(
        Finding(
          FindingLevel.passed,
          'Purchase stream listener',
          'A purchase update stream listener was detected.',
          id: 'transaction-purchase-stream',
          file: s.purchaseStreamFile,
          line: s.purchaseStreamLine,
        ),
      );
    } else {
      findings.add(
        Finding(
          FindingLevel.warning,
          'Purchase stream listener',
          'No purchaseUpdatedStream / purchase stream listener was detected.',
          id: 'transaction-purchase-stream',
          fix: 'Listen to purchase updates and handle all purchase statuses.',
        ),
      );
    }

    // Entitlement before verification — genuine risk for digital goods.
    if (s.hasEntitlementGrant) {
      if (!s.hasBackendVerify) {
        findings.add(
          Finding(
            FindingLevel.error,
            'Entitlement before verification',
            'Client-side entitlement granting was detected without a detectable backend verification path.',
            id: 'transaction-entitlement-before-verify',
            file: s.entitlementFile,
            line: s.entitlementLine,
            classification: 'client-side-entitlement',
            fix:
                'Verify the purchase on your backend before unlocking digital content or subscriptions.',
          ),
        );
      } else if (s.entitlementBeforeVerify) {
        findings.add(
          Finding(
            FindingLevel.error,
            'Entitlement before verification',
            'Entitlement appears to be granted in client code before backend verification runs.',
            id: 'transaction-entitlement-before-verify',
            file: s.entitlementFile,
            line: s.entitlementLine,
            classification: 'client-side-entitlement',
            fix:
                'Grant entitlements only after the backend confirms the purchase token/receipt.',
          ),
        );
      } else {
        findings.add(
          Finding(
            FindingLevel.passed,
            'Entitlement verification order',
            'Backend verification appears present before or alongside entitlement handling.',
            id: 'transaction-entitlement-before-verify',
            file: s.verifyFile,
            line: s.verifyLine,
          ),
        );
      }
    } else if (!s.hasBackendVerify) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'Backend purchase verification',
          'No backend verification path was detectable for digital purchases.',
          id: 'transaction-backend-verify',
          fix:
              'Send purchase tokens/receipts to your server and verify with Google/Apple before unlocking content.',
        ),
      );
    } else {
      findings.add(
        Finding(
          FindingLevel.passed,
          'Backend purchase verification',
          'A backend verification path was detected.',
          id: 'transaction-backend-verify',
          file: s.verifyFile,
          line: s.verifyLine,
        ),
      );
    }

    if (!s.hasCompletePurchase) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'Purchase acknowledgement',
          'Purchase completion / acknowledgement (completePurchase) was not detectable.',
          id: 'transaction-acknowledgement',
          fix:
              'Call completePurchase / acknowledge after successful handling to avoid repurchase issues.',
        ),
      );
    } else {
      findings.add(
        Finding(
          FindingLevel.passed,
          'Purchase acknowledgement',
          'Purchase completion / acknowledgement handling was detected.',
          id: 'transaction-acknowledgement',
          file: s.completeFile,
          line: s.completeLine,
        ),
      );
    }

    if (s.hasBackendVerify && s.hasPurchaseToken) {
      findings.add(
        Finding(
          FindingLevel.passed,
          'Purchase token handling',
          'Purchase token / verification data extraction was detected (values are not shown).',
          id: 'transaction-purchase-token',
          file: s.tokenFile,
          line: s.tokenLine,
          classification: 'purchase-token-reference',
        ),
      );
    }

    if (s.hasDuplicateHandling) {
      findings.add(
        Finding(
          FindingLevel.passed,
          'Duplicate purchase handling',
          'Possible duplicate purchase-token handling was detected.',
          id: 'transaction-duplicate-token',
          file: s.duplicateFile,
          line: s.duplicateLine,
        ),
      );
    }

    final missingStates = <String>[
      if (!s.hasPending) 'pending',
      if (!s.hasCanceled) 'cancelled',
      if (!s.hasRestored && !s.hasRestorePurchases) 'restored',
    ];
    if (missingStates.isNotEmpty) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'Purchase state handling',
          'Pending/cancelled/restored purchase states are not fully handled (missing: ${missingStates.join(', ')}).',
          id: 'transaction-purchase-states',
          fix:
              'Handle PurchaseStatus.pending, canceled/cancelled, and restored (plus restorePurchases).',
        ),
      );
    } else {
      findings.add(
        Finding(
          FindingLevel.passed,
          'Purchase state handling',
          'Pending, cancelled, and restored purchase handling was detected.',
          id: 'transaction-purchase-states',
          file: s.pendingFile ?? s.canceledFile ?? s.restoredFile,
          line: s.pendingLine ?? s.canceledLine ?? s.restoredLine,
        ),
      );
    }

    if (s.hasRestorePurchases) {
      findings.add(
        Finding(
          FindingLevel.passed,
          'Restore purchases',
          'restorePurchases handling was detected.',
          id: 'transaction-restore-purchases',
          file: s.restoreFile,
          line: s.restoreLine,
        ),
      );
    } else if (transactionType == TransactionType.subscription ||
        transactionType == TransactionType.digitalGoods) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'Restore purchases',
          'No restorePurchases handling was detected.',
          id: 'transaction-restore-purchases',
          fix: 'Implement restore purchases for reinstalls and new devices.',
        ),
      );
    }
  }

  void _analyzePhysical(_Signals s, List<Finding> findings) {
    // Physical goods / food delivery / rides must not require Play Billing.
    if (s.hasBillingDependency) {
      findings.add(
        Finding(
          FindingLevel.info,
          'Billing dependency',
          'in_app_purchase / Play Billing dependency is present, but transaction_type is physical_goods (Play Billing is not required for physical goods).',
          id: 'transaction-billing-dependency',
          file: s.billingDepFile,
          line: s.billingDepLine,
        ),
      );
    }

    final hasStaticEvidence = s.hasExternalPayment || s.hasCashOnDelivery;
    if (hasStaticEvidence) {
      findings.add(
        Finding(
          FindingLevel.passed,
          'External payment flow',
          'Static payment-flow evidence was detected for physical goods '
              '(gateway/WebView dependency, payment symbols, API paths, or COD terms). '
              'This does not prove secure transaction handling.',
          id: 'external-payment-flow-detected',
          file: s.externalFile ?? s.codFile,
          line: s.externalLine ?? s.codLine,
        ),
      );
    }

    if (paymentFlows.isNotEmpty) {
      final labels = paymentFlows.map(_paymentFlowLabel).toList()..sort();
      findings.add(
        Finding(
          FindingLevel.passed,
          'Payment flow declared',
          'payment_flows is project-declared (${labels.join(', ')}) and not automatically verified. '
              'Declarations are not proof of secure transaction handling.',
          id: 'payment-flow-declared',
        ),
      );
    }

    if (paymentFlows.contains(PaymentFlow.cashOnDelivery)) {
      findings.add(
        const Finding(
          FindingLevel.passed,
          'Cash on delivery declared',
          'cash_on_delivery is project-declared in payment_flows and not automatically verified.',
          id: 'cash-on-delivery-declared',
        ),
      );
    }

    if (!hasStaticEvidence && paymentFlows.isEmpty) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'External payment flow',
          'No external payment flow was detected for physical_goods, and no payment_flows declaration was found.',
          id: 'external-payment-flow-not-detected',
          fix:
              'Add gateway/WebView payment code, COD handling, or declare payment_flows in `.release-doctor.yaml`. Google Play Billing is not required for physical goods.',
        ),
      );
    }
  }

  String _paymentFlowLabel(PaymentFlow flow) => switch (flow) {
        PaymentFlow.externalGateway => 'external_gateway',
        PaymentFlow.cashOnDelivery => 'cash_on_delivery',
        PaymentFlow.offlinePayment => 'offline_payment',
        PaymentFlow.noInAppPayment => 'no_in_app_payment',
      };

  void _analyzeExternal(_Signals s, List<Finding> findings) {
    if (s.hasExternalPayment) {
      findings.add(
        Finding(
          FindingLevel.passed,
          'External payment handling',
          'External payment gateway handling was detected.',
          id: 'transaction-external-payment',
          file: s.externalFile,
          line: s.externalLine,
        ),
      );
    } else {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'External payment handling',
          'transaction_type is external_payment but no external gateway usage was detected.',
          id: 'transaction-external-payment',
          fix: 'Wire up your payment SDK and server-side payment confirmation.',
        ),
      );
    }
  }

  void _analyzeUnknown(_Signals s, List<Finding> findings) {
    findings.add(
      const Finding(
        FindingLevel.warning,
        'Transaction type not configured',
        'transaction_type is unknown. Add `transaction_type` to `.release-doctor.yaml` (digital_goods, subscription, physical_goods, or external_payment) so billing checks match your app.',
        id: 'transaction-type-not-configured',
        fix: 'Example: transaction_type: physical_goods',
      ),
    );

    // If Play Billing signals exist without a declared type, apply soft digital warnings.
    if (s.hasBillingDependency || s.hasPurchaseStream) {
      if (s.hasEntitlementGrant && !s.hasBackendVerify) {
        findings.add(
          Finding(
            FindingLevel.error,
            'Entitlement before verification',
            'Client-side entitlement granting was detected without a detectable backend verification path.',
            id: 'transaction-entitlement-before-verify',
            file: s.entitlementFile,
            line: s.entitlementLine,
            classification: 'client-side-entitlement',
            fix:
                'Verify purchases on your backend before unlocking digital content, or set transaction_type: physical_goods if this app sells physical goods only.',
          ),
        );
      }
      if (!s.hasCompletePurchase) {
        findings.add(
          Finding(
            FindingLevel.warning,
            'Purchase acknowledgement',
            'Purchase completion / acknowledgement was not detectable.',
            id: 'transaction-acknowledgement',
            fix: 'Call completePurchase after handling a successful purchase.',
          ),
        );
      }
    }
  }

  String _typeLabel() => switch (transactionType) {
        TransactionType.digitalGoods => 'digital_goods',
        TransactionType.subscription => 'subscription',
        TransactionType.physicalGoods => 'physical_goods',
        TransactionType.externalPayment => 'external_payment',
        TransactionType.unknown => 'unknown',
      };

  Future<_Signals> _scan(Directory project) async {
    final signals = _Signals();

    final pubspec = File(
      '${project.path}${Platform.pathSeparator}pubspec.yaml',
    );
    if (await pubspec.exists()) {
      final text = await pubspec.readAsString();
      final billing = _billingDeps.firstMatch(text);
      if (billing != null) {
        signals.hasBillingDependency = true;
        signals.billingDepFile = 'pubspec.yaml';
        signals.billingDepLine = Evidence.lineOfOffset(text, billing.start);
      }
      final external = _externalPaymentDeps.firstMatch(text);
      if (external != null) {
        signals.hasExternalPayment = true;
        signals.externalFile = 'pubspec.yaml';
        signals.externalLine = Evidence.lineOfOffset(text, external.start);
      }
    }

    final lib = Directory('${project.path}${Platform.pathSeparator}lib');
    if (!await lib.exists()) return signals;

    await for (final entity in lib.list(recursive: true, followLinks: false)) {
      if (entity is! File || !entity.path.endsWith('.dart')) continue;
      final relative = Evidence.relativePath(project, entity);
      final text = await entity.readAsString();

      void hit(
        RegExp pattern,
        void Function(int line) assign, {
        required bool Function() already,
      }) {
        if (already()) return;
        final match = pattern.firstMatch(text);
        if (match == null) return;
        assign(Evidence.lineOfOffset(text, match.start));
      }

      if (!signals.hasPurchaseStream) {
        final m = _purchaseStream.firstMatch(text);
        if (m != null) {
          signals.hasPurchaseStream = true;
          signals.purchaseStreamFile = relative;
          signals.purchaseStreamLine = Evidence.lineOfOffset(text, m.start);
        }
      }

      hit(
        _completePurchase,
        (line) {
          signals.hasCompletePurchase = true;
          signals.completeFile = relative;
          signals.completeLine = line;
        },
        already: () => signals.hasCompletePurchase,
      );

      hit(
        _backendVerify,
        (line) {
          signals.hasBackendVerify = true;
          signals.verifyFile = relative;
          signals.verifyLine = line;
        },
        already: () => signals.hasBackendVerify,
      );

      hit(
        _purchaseToken,
        (line) {
          signals.hasPurchaseToken = true;
          signals.tokenFile = relative;
          signals.tokenLine = line;
        },
        already: () => signals.hasPurchaseToken,
      );

      hit(
        _entitlementGrant,
        (line) {
          signals.hasEntitlementGrant = true;
          signals.entitlementFile = relative;
          signals.entitlementLine = line;
        },
        already: () => signals.hasEntitlementGrant,
      );

      hit(
        _duplicateToken,
        (line) {
          signals.hasDuplicateHandling = true;
          signals.duplicateFile = relative;
          signals.duplicateLine = line;
        },
        already: () => signals.hasDuplicateHandling,
      );

      hit(
        _restorePurchases,
        (line) {
          signals.hasRestorePurchases = true;
          signals.restoreFile = relative;
          signals.restoreLine = line;
        },
        already: () => signals.hasRestorePurchases,
      );

      hit(
        _pendingState,
        (line) {
          signals.hasPending = true;
          signals.pendingFile = relative;
          signals.pendingLine = line;
        },
        already: () => signals.hasPending,
      );

      hit(
        _canceledState,
        (line) {
          signals.hasCanceled = true;
          signals.canceledFile = relative;
          signals.canceledLine = line;
        },
        already: () => signals.hasCanceled,
      );

      hit(
        _restoredState,
        (line) {
          signals.hasRestored = true;
          signals.restoredFile = relative;
          signals.restoredLine = line;
        },
        already: () => signals.hasRestored,
      );

      void markExternal(RegExp pattern) {
        if (signals.hasExternalPayment) return;
        final m = pattern.firstMatch(text);
        if (m == null) return;
        signals.hasExternalPayment = true;
        signals.externalFile = relative;
        signals.externalLine = Evidence.lineOfOffset(text, m.start);
      }

      markExternal(_externalPaymentUsage);
      markExternal(_paymentFlowSymbols);
      markExternal(_paymentApiPath);
      markExternal(_externalPaymentDeps);

      if (!signals.hasCashOnDelivery) {
        final m = _cashOnDelivery.firstMatch(text);
        if (m != null) {
          signals.hasCashOnDelivery = true;
          signals.codFile = relative;
          signals.codLine = Evidence.lineOfOffset(text, m.start);
        }
      }

      // Same-file ordering heuristic for entitlement vs verification.
      if (_purchaseStream.hasMatch(text) &&
          _entitlementGrant.hasMatch(text) &&
          _backendVerify.hasMatch(text)) {
        final grant = _entitlementGrant.firstMatch(text)!;
        final verify = _backendVerify.firstMatch(text)!;
        if (grant.start < verify.start) {
          signals.entitlementBeforeVerify = true;
          signals.entitlementFile = relative;
          signals.entitlementLine = Evidence.lineOfOffset(text, grant.start);
        }
      } else if (_purchaseStream.hasMatch(text) &&
          _entitlementGrant.hasMatch(text) &&
          !_backendVerify.hasMatch(text)) {
        // Grant inside purchase handling file with no local verify.
        signals.entitlementBeforeVerify = true;
        final grant = _entitlementGrant.firstMatch(text)!;
        signals.entitlementFile ??= relative;
        signals.entitlementLine ??= Evidence.lineOfOffset(text, grant.start);
      }
    }

    return signals;
  }
}

class _Signals {
  bool hasBillingDependency = false;
  String? billingDepFile;
  int? billingDepLine;

  bool hasPurchaseStream = false;
  String? purchaseStreamFile;
  int? purchaseStreamLine;

  bool hasCompletePurchase = false;
  String? completeFile;
  int? completeLine;

  bool hasBackendVerify = false;
  String? verifyFile;
  int? verifyLine;

  bool hasPurchaseToken = false;
  String? tokenFile;
  int? tokenLine;

  bool hasEntitlementGrant = false;
  String? entitlementFile;
  int? entitlementLine;
  bool entitlementBeforeVerify = false;

  bool hasDuplicateHandling = false;
  String? duplicateFile;
  int? duplicateLine;

  bool hasRestorePurchases = false;
  String? restoreFile;
  int? restoreLine;

  bool hasPending = false;
  String? pendingFile;
  int? pendingLine;

  bool hasCanceled = false;
  String? canceledFile;
  int? canceledLine;

  bool hasRestored = false;
  String? restoredFile;
  int? restoredLine;

  bool hasExternalPayment = false;
  String? externalFile;
  int? externalLine;

  bool hasCashOnDelivery = false;
  String? codFile;
  int? codLine;
}
