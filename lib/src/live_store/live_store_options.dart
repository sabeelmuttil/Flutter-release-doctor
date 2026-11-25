enum StoreTarget { google, apple, both }

/// CLI / runtime options for optional live store verification.
class LiveStoreOptions {
  const LiveStoreOptions({
    this.online = false,
    this.store = StoreTarget.both,
    this.enabled = true,
  });

  /// When false (default), no network calls are made.
  final bool online;

  final StoreTarget store;

  /// When false (`--no-store-check`), skip live store verification entirely.
  final bool enabled;

  static const offline = LiveStoreOptions();

  bool get shouldRun => online && enabled;

  bool get includeGoogle =>
      shouldRun && (store == StoreTarget.google || store == StoreTarget.both);

  bool get includeApple =>
      shouldRun && (store == StoreTarget.apple || store == StoreTarget.both);
}
