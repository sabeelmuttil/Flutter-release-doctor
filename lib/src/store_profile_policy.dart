import 'package:flutter_release_doctor/src/doctor_config.dart';
import 'package:flutter_release_doctor/src/finding.dart';

/// Applies [StoreProfile] policy to avoid irrelevant cross-project findings.
///
/// Does not hide non-suppressible security findings.
class StoreProfilePolicy {
  List<Finding> apply(DoctorConfig config, List<Finding> findings) {
    final profile = config.storeProfile;
    final result = <Finding>[];

    for (final finding in findings) {
      if (nonSuppressibleFindingIds.contains(finding.id)) {
        result.add(
          finding.copyWith(
            confidence: FindingConfidence.high,
            source: finding.source,
          ),
        );
        continue;
      }

      final adjusted = _adjust(profile, config, finding);
      if (adjusted != null) {
        result.add(adjusted);
      }
    }
    return result;
  }

  Finding? _adjust(
    StoreProfile profile,
    DoctorConfig config,
    Finding finding,
  ) {
    // Physical goods: drop digital billing/IAP risk findings.
    if (profile.isPhysicalGoodsOnly ||
        config.transactionType == TransactionType.physicalGoods) {
      if (finding.id == 'play-billing-bypass-risk' ||
          finding.id == 'apple-iap-missing' ||
          finding.id == 'transaction-billing-missing') {
        return null;
      }
    }

    // First-party auth only: do not WARN about Sign in with Apple.
    if (profile.isFirstPartyAuthOnly &&
        finding.id == 'apple-sign-in-with-apple-review' &&
        finding.level == FindingLevel.warning) {
      return finding.copyWith(
        level: FindingLevel.manualReview,
        confidence: FindingConfidence.low,
        source: FindingSource.projectConfig,
        detail:
            '${finding.detail} Profile authentication is ${profile.authentication.name}; '
            'Sign in with Apple is not automatically required for email/password or phone OTP. '
            'Needs verification if custom social OAuth exists.',
        guideline: 'Apple App Review 4.8 Login Services',
        evidenceSummary:
            'store_profile.authentication declares first-party login',
      );
    }

    // Declared location use: location permission is expected → manual review.
    if (profile.usesLocation == true &&
        finding.id == 'android-sensitive-permissions' &&
        finding.detail.contains('LOCATION')) {
      return finding.copyWith(
        level: FindingLevel.manualReview,
        confidence: FindingConfidence.low,
        source: FindingSource.projectConfig,
        detail:
            '${finding.detail} store_profile.uses_location=true, so location permission is expected. '
            'Verify Play Data Safety / App Privacy disclosures manually — not a release blocker by itself.',
        guideline: 'Google Play User Data / Data Safety',
        evidenceSummary:
            'Location permission present; profile declares uses_location',
      );
    }

    // Universal Links not used: never keep associated-domain WARNINGs.
    if (profile.usesUniversalLinks == false &&
        finding.id == 'ios-associated-domains' &&
        finding.level == FindingLevel.warning) {
      return finding.copyWith(
        level: FindingLevel.manualReview,
        confidence: FindingConfidence.low,
        source: FindingSource.projectConfig,
        detail:
            'store_profile.uses_universal_links=false. Universal Links are disabled by project profile. '
            'This signal is for manual review only (not a release blocker).',
        evidenceSummary: 'Profile declares Universal Links are not used',
      );
    }

    // Android App Links explicitly disabled.
    if (profile.usesAndroidAppLinks == false &&
        (finding.id == 'android-app-links-host' ||
            finding.id == 'android-app-links-autoverify') &&
        finding.level == FindingLevel.warning) {
      return finding.copyWith(
        level: FindingLevel.info,
        confidence: FindingConfidence.low,
        source: FindingSource.projectConfig,
        detail:
            '${finding.detail} store_profile.uses_android_app_links=false, so this is informational only.',
        evidenceSummary: 'Profile declares Android App Links are not used',
      );
    }

    // CI explicitly not required.
    if (profile.ciRequired == false &&
        (finding.id == 'missing-ci-workflow' ||
            finding.id == 'ci-workflows-empty') &&
        finding.level == FindingLevel.warning) {
      return finding.copyWith(
        level: FindingLevel.info,
        confidence: FindingConfidence.low,
        source: FindingSource.projectConfig,
        detail:
            '${finding.detail} store_profile.ci_required=false, so missing CI is informational only.',
        evidenceSummary: 'Profile declares CI is not required',
      );
    }

    // UGC explicitly false: drop moderation warnings.
    if (profile.hasUserGeneratedContent == false &&
        finding.id == 'apple-ugc-moderation-review') {
      return null;
    }

    // Reviewer demo from profile.
    if (profile.hasUserAccounts == true &&
        profile.reviewerDemoAccount == true &&
        finding.id == 'apple-reviewer-access-missing') {
      return null;
    }

    // Medium-confidence store warnings: require verification language.
    if (finding.level == FindingLevel.warning &&
        finding.confidence == FindingConfidence.medium &&
        finding.guideline != null &&
        !finding.detail.contains('Needs verification')) {
      return finding.copyWith(
        detail: '${finding.detail} Needs verification.',
      );
    }

    return finding;
  }
}
