enum FindingLevel { error, warning, info, passed }

class Finding {
  const Finding(
    this.level,
    this.title,
    this.detail, {
    required this.id,
    this.fix,
    this.suppressed = false,
    this.file,
    this.line,
    this.classification,
  });

  /// Stable machine-readable finding identifier (kebab-case).
  final String id;
  final FindingLevel level;
  final String title;
  final String detail;
  final String? fix;

  /// True when an ERROR was downgraded by project `ignore` configuration.
  final bool suppressed;

  /// Optional repo-relative path for actionable evidence.
  final String? file;

  /// Optional 1-based line number for actionable evidence.
  final int? line;

  /// Redacted classification for secret findings (never a secret value).
  final String? classification;

  Finding copyWith({
    FindingLevel? level,
    String? title,
    String? detail,
    String? id,
    String? fix,
    bool? suppressed,
    String? file,
    int? line,
    String? classification,
  }) {
    return Finding(
      level ?? this.level,
      title ?? this.title,
      detail ?? this.detail,
      id: id ?? this.id,
      fix: fix ?? this.fix,
      suppressed: suppressed ?? this.suppressed,
      file: file ?? this.file,
      line: line ?? this.line,
      classification: classification ?? this.classification,
    );
  }

  String? get evidenceLabel {
    if (file == null) return null;
    final location = line == null ? file! : '$file:$line';
    if (classification == null || classification!.isEmpty) return location;
    return '$location ($classification)';
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'level': level.name,
        'title': title,
        'detail': detail,
        'fix': fix,
        'suppressed': suppressed,
        'file': file,
        'line': line,
        'classification': classification,
      };
}

/// Finding IDs that configuration must not suppress or downgrade below error
/// when they are errors (hard-coded secrets / signing material).
const nonSuppressibleFindingIds = <String>{
  'hard-coded-secret',
  'ci-hard-coded-secret',
};
