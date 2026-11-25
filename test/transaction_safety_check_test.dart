import 'dart:io';

import 'package:flutter_release_doctor/flutter_release_doctor.dart';
import 'package:test/test.dart';

void main() {
  late Directory tempRoot;

  setUp(() async {
    tempRoot = await Directory.systemTemp.createTemp('release_doctor_txn_');
  });

  tearDown(() async {
    if (await tempRoot.exists()) {
      await tempRoot.delete(recursive: true);
    }
  });

  test('PASS for secure digital purchase flow', () async {
    final project = await _baseProject(
      tempRoot,
      'secure_digital',
      transactionType: 'digital_goods',
      pubspecExtra: '''
dependencies:
  in_app_purchase: ^3.2.0
''',
    );
    await _writeLib(project, 'billing.dart', '''
import 'package:in_app_purchase/in_app_purchase.dart';

Future<void> listenPurchases() async {
  InAppPurchase.instance.purchaseStream.listen((purchases) async {
    for (final purchase in purchases) {
      if (purchase.status == PurchaseStatus.pending) {
        continue;
      }
      if (purchase.status == PurchaseStatus.canceled) {
        continue;
      }
      if (purchase.status == PurchaseStatus.restored) {
        await verifyPurchaseOnServer(purchase.verificationData.serverVerificationData);
        continue;
      }
      if (purchase.status == PurchaseStatus.purchased) {
        final token = purchase.verificationData.serverVerificationData;
        final ok = await verifyPurchaseOnServer(token);
        if (!ok) return;
        await grantEntitlement(purchase.productID);
        await InAppPurchase.instance.completePurchase(purchase);
      }
    }
  });
}

Future<void> restore() => InAppPurchase.instance.restorePurchases();

Future<bool> verifyPurchaseOnServer(String serverVerificationData) async => true;
Future<void> grantEntitlement(String productId) async {}
''');

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.where(
        (f) =>
            f.id == 'transaction-entitlement-before-verify' &&
            f.level == FindingLevel.error,
      ),
      isEmpty,
    );
    expect(
      report.findings.where(
        (f) =>
            f.id == 'transaction-acknowledgement' &&
            f.level == FindingLevel.passed,
      ),
      isNotEmpty,
    );
    expect(
      report.findings.where(
        (f) =>
            f.id == 'transaction-backend-verify' &&
                f.level == FindingLevel.passed ||
            (f.id == 'transaction-entitlement-before-verify' &&
                f.level == FindingLevel.passed),
      ),
      isNotEmpty,
    );
    expect(
      report.findings.where(
        (f) =>
            f.id == 'transaction-purchase-states' &&
            f.level == FindingLevel.passed,
      ),
      isNotEmpty,
    );
    expect(report.toJsonString().toLowerCase(), isNot(contains('tok_')));
  });

  test('ERROR for unsafe client-side entitlement before verification',
      () async {
    final project = await _baseProject(
      tempRoot,
      'unsafe_entitle',
      transactionType: 'digital_goods',
      pubspecExtra: '''
dependencies:
  in_app_purchase: ^3.2.0
''',
    );
    await _writeLib(project, 'unsafe.dart', '''
import 'package:in_app_purchase/in_app_purchase.dart';

void listen() {
  InAppPurchase.instance.purchaseStream.listen((purchases) {
    for (final purchase in purchases) {
      unlockPremium();
      isPremium = true;
    }
  });
}

void unlockPremium() {}
bool isPremium = false;
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.id == 'transaction-entitlement-before-verify',
    );
    expect(finding.level, FindingLevel.error);
    expect(finding.file, contains('unsafe.dart'));
    expect(finding.line, isNotNull);
    expect(finding.classification, 'client-side-entitlement');
    expect(report.hasErrors, isTrue);
  });

  test('WARNING when purchase acknowledgement is missing', () async {
    final project = await _baseProject(
      tempRoot,
      'missing_ack',
      transactionType: 'subscription',
      pubspecExtra: '''
dependencies:
  in_app_purchase: ^3.2.0
''',
    );
    await _writeLib(project, 'sub.dart', '''
import 'package:in_app_purchase/in_app_purchase.dart';

void listen() {
  InAppPurchase.instance.purchaseUpdatedStream.listen((purchases) async {
    for (final purchase in purchases) {
      if (purchase.status == PurchaseStatus.pending) continue;
      if (purchase.status == PurchaseStatus.canceled) continue;
      if (purchase.status == PurchaseStatus.restored) {
        await verifyPurchaseOnServer(purchase.purchaseID ?? '');
        continue;
      }
      final token = purchase.verificationData.serverVerificationData;
      await verifyPurchaseOnServer(token);
    }
  });
}

Future<void> restorePurchases() => InAppPurchase.instance.restorePurchases();
Future<bool> verifyPurchaseOnServer(String data) async => true;
''');

    final report = await ReleaseDoctor().check(project);
    final finding = report.findings.singleWhere(
      (f) => f.id == 'transaction-acknowledgement',
    );
    expect(finding.level, FindingLevel.warning);
    expect(
      report.findings.where(
        (f) =>
            f.id == 'transaction-entitlement-before-verify' &&
            f.level == FindingLevel.error,
      ),
      isEmpty,
    );
  });

  test('PASS for physical-goods external payment without Play Billing',
      () async {
    final project = await _baseProject(
      tempRoot,
      'physical_goods',
      transactionType: 'physical_goods',
      pubspecExtra: '''
dependencies:
  razorpay_flutter: ^1.3.0
''',
    );
    await _writeLib(project, 'checkout.dart', '''
import 'package:razorpay_flutter/razorpay_flutter.dart';

void pay() {
  final razorpay = Razorpay();
  razorpay.openCheckout(<String, dynamic>{
    'amount': 100,
  });
}
''');

    final report = await ReleaseDoctor().check(project);
    _expectTransactionTypeSummary(
        report, 'physical_goods', FindingLevel.passed);
    expect(
      report.findings.where((f) => f.id == 'transaction-billing-missing'),
      isEmpty,
    );
    final flow = report.findings.singleWhere(
      (f) => f.id == 'external-payment-flow-detected',
    );
    expect(flow.level, FindingLevel.passed);
    expect(report.toConsole(), contains('external-payment-flow-detected'));
    expect(report.toMarkdown(), contains('external-payment-flow-detected'));
    expect(report.toJsonString(), contains('external-payment-flow-detected'));
  });

  test('WARNING when physical_goods has no evidence and no declaration',
      () async {
    final project = await _baseProject(
      tempRoot,
      'physical_no_pay',
      transactionType: 'physical_goods',
    );

    final report = await ReleaseDoctor().check(project);
    _expectTransactionTypeSummary(
        report, 'physical_goods', FindingLevel.passed);
    expect(
      report.findings.where((f) => f.id == 'transaction-billing-missing'),
      isEmpty,
    );
    final flow = report.findings.singleWhere(
      (f) => f.id == 'external-payment-flow-not-detected',
    );
    expect(flow.level, FindingLevel.warning);
    expect(report.toMarkdown(),
        contains('Transaction type configured as physical_goods.'));
    expect(report.toJsonString(), contains('"id": "transaction-type"'));
  });

  test('PASS when gateway dependency name is detected in pubspec', () async {
    final project = await _baseProject(
      tempRoot,
      'gateway_dep',
      transactionType: 'physical_goods',
      pubspecExtra: '''
dependencies:
  flutter_stripe: ^10.0.0
  webview_flutter: ^4.0.0
''',
    );

    final report = await ReleaseDoctor().check(project);
    final flow = report.findings.singleWhere(
      (f) => f.id == 'external-payment-flow-detected',
    );
    expect(flow.level, FindingLevel.passed);
    expect(flow.file, 'pubspec.yaml');
    expect(flow.line, isNotNull);
    expect(
      report.findings
          .where((f) => f.id == 'external-payment-flow-not-detected'),
      isEmpty,
    );
  });

  test('PASS when payment API path strings are detected', () async {
    final project = await _baseProject(
      tempRoot,
      'payment_api',
      transactionType: 'physical_goods',
    );
    await _writeLib(project, 'api.dart', '''
Future<void> placeOrder() async {
  const path = '/api/v1/order-payment';
  await post(path);
}

Future<void> post(String path) async {}
''');

    final report = await ReleaseDoctor().check(project);
    final flow = report.findings.singleWhere(
      (f) => f.id == 'external-payment-flow-detected',
    );
    expect(flow.level, FindingLevel.passed);
    expect(flow.file, contains('api.dart'));
    expect(flow.line, isNotNull);
  });

  test('PASS when cash-on-delivery terms are detected in code', () async {
    final project = await _baseProject(
      tempRoot,
      'cod_code',
      transactionType: 'physical_goods',
    );
    await _writeLib(project, 'checkout.dart', '''
enum PayMethod { online, cashOnDelivery }

bool isCod(PayMethod method) => method == PayMethod.cashOnDelivery;
''');

    final report = await ReleaseDoctor().check(project);
    final flow = report.findings.singleWhere(
      (f) => f.id == 'external-payment-flow-detected',
    );
    expect(flow.level, FindingLevel.passed);
    expect(flow.file, contains('checkout.dart'));
    expect(flow.line, isNotNull);
  });

  test('PASS payment-flow-declared for configured external_gateway', () async {
    final project = await _baseProject(
      tempRoot,
      'declared_gateway',
      transactionType: 'physical_goods',
      paymentFlowsYaml: '''
payment_flows:
  - external_gateway
''',
    );

    final report = await ReleaseDoctor().check(project);
    final declared = report.findings.singleWhere(
      (f) => f.id == 'payment-flow-declared',
    );
    expect(declared.level, FindingLevel.passed);
    expect(declared.detail, contains('project-declared'));
    expect(declared.detail, contains('not automatically verified'));
    expect(
      report.findings
          .where((f) => f.id == 'external-payment-flow-not-detected'),
      isEmpty,
    );
  });

  test('PASS cash-on-delivery-declared when COD is configured', () async {
    final project = await _baseProject(
      tempRoot,
      'declared_cod',
      transactionType: 'physical_goods',
      paymentFlowsYaml: '''
payment_flows:
  - cash_on_delivery
''',
    );

    final report = await ReleaseDoctor().check(project);
    expect(
      report.findings.singleWhere((f) => f.id == 'payment-flow-declared').level,
      FindingLevel.passed,
    );
    final cod = report.findings.singleWhere(
      (f) => f.id == 'cash-on-delivery-declared',
    );
    expect(cod.level, FindingLevel.passed);
    expect(cod.detail, contains('project-declared'));
    expect(
      report.findings
          .where((f) => f.id == 'external-payment-flow-not-detected'),
      isEmpty,
    );
  });

  test('WARNING when transaction_type is unknown / not configured', () async {
    final project = await _baseProject(
      tempRoot,
      'unknown_txn',
      transactionType: 'unknown',
      pubspecExtra: '''
dependencies:
  in_app_purchase: ^3.2.0
''',
    );
    await _writeLib(project, 'pay.dart', '''
import 'package:in_app_purchase/in_app_purchase.dart';

void listen() {
  InAppPurchase.instance.purchaseStream.listen((_) {});
}
''');

    final report = await ReleaseDoctor().check(project);
    _expectTransactionTypeSummary(report, 'unknown', FindingLevel.info);
    final notConfigured = report.findings.singleWhere(
      (f) => f.id == 'transaction-type-not-configured',
    );
    expect(notConfigured.level, FindingLevel.warning);
    expect(notConfigured.detail, contains('.release-doctor.yaml'));
    expect(report.toConsole(), contains('transaction-type-not-configured'));
    expect(report.toMarkdown(), contains('transaction-type-not-configured'));
    expect(report.toJsonString(), contains('transaction-type-not-configured'));
  });

  test('transaction-type summary appears for digital_goods', () async {
    final project = await _baseProject(
      tempRoot,
      'digital_summary',
      transactionType: 'digital_goods',
      pubspecExtra: '''
dependencies:
  in_app_purchase: ^3.2.0
''',
    );
    await _writeLib(project, 'pay.dart', '''
import 'package:in_app_purchase/in_app_purchase.dart';

void listen() {
  InAppPurchase.instance.purchaseStream.listen((_) {});
  InAppPurchase.instance.completePurchase;
}
''');

    final report = await ReleaseDoctor().check(project);
    _expectTransactionTypeSummary(report, 'digital_goods', FindingLevel.passed);
    expect(
      report.findings.where((f) => f.id == 'transaction-type'),
      hasLength(1),
    );
  });
}

void _expectTransactionTypeSummary(
  DoctorReport report,
  String type,
  FindingLevel level,
) {
  final summary =
      report.findings.singleWhere((f) => f.id == 'transaction-type');
  expect(summary.level, level);
  expect(summary.detail, 'Transaction type configured as $type.');
  expect(report.toConsole(), contains('Transaction type configured as $type.'));
  expect(
      report.toMarkdown(), contains('Transaction type configured as $type.'));
  expect(
      report.toJsonString(), contains('Transaction type configured as $type.'));
}

Future<Directory> _baseProject(
  Directory tempRoot,
  String name, {
  required String transactionType,
  String pubspecExtra = '',
  String paymentFlowsYaml = '',
}) async {
  final project = Directory('${tempRoot.path}${Platform.pathSeparator}$name');
  await project.create(recursive: true);
  await File('${project.path}${Platform.pathSeparator}pubspec.yaml')
      .writeAsString('''
name: $name
description: Fixture
version: 1.0.0+1
environment:
  sdk: ^3.5.0
$pubspecExtra
''');
  await File(
    '${project.path}${Platform.pathSeparator}.release-doctor.yaml',
  ).writeAsString('''
version: 1
transaction_type: $transactionType
$paymentFlowsYaml
''');
  return project;
}

Future<void> _writeLib(
  Directory project,
  String name,
  String contents,
) async {
  final lib = Directory('${project.path}${Platform.pathSeparator}lib');
  await lib.create(recursive: true);
  await File('${lib.path}${Platform.pathSeparator}$name')
      .writeAsString(contents);
}
