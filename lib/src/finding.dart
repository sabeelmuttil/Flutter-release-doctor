enum FindingLevel { error, warning, info, passed }

class Finding {
  const Finding(
    this.level,
    this.title,
    this.detail, {
    required this.id,
    this.fix,
  });

  /// Stable machine-readable finding identifier (kebab-case).
  final String id;
  final FindingLevel level;
  final String title;
  final String detail;
  final String? fix;

  Finding copyWith({
    FindingLevel? level,
    String? title,
    String? detail,
    String? id,
    String? fix,
  }) {
    return Finding(
      level ?? this.level,
      title ?? this.title,
      detail ?? this.detail,
      id: id ?? this.id,
      fix: fix ?? this.fix,
    );
  }
}

/// Finding IDs that configuration must not suppress or downgrade below error
/// when they are errors (hard-coded secrets / signing material).
const nonSuppressibleFindingIds = <String>{
  'hard-coded-secret',
  'ci-hard-coded-secret',
};
