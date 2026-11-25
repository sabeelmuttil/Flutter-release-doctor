import 'dart:convert';
import 'dart:io';

/// Minimal HTTP response for injectable live-store clients.
class StoreHttpResponse {
  const StoreHttpResponse({
    required this.statusCode,
    required this.body,
  });

  final int statusCode;
  final String body;

  Map<String, dynamic>? get jsonBody {
    try {
      final decoded = jsonDecode(body);
      if (decoded is Map<String, dynamic>) return decoded;
      if (decoded is Map) {
        return decoded.map((k, v) => MapEntry(k.toString(), v));
      }
    } catch (_) {}
    return null;
  }
}

/// Injectable HTTP surface so tests never hit the network.
abstract class StoreHttpClient {
  Future<StoreHttpResponse> get(
    Uri uri, {
    Map<String, String>? headers,
  });

  Future<StoreHttpResponse> post(
    Uri uri, {
    Map<String, String>? headers,
    String? body,
  });
}

/// Production client using `dart:io` [HttpClient].
class DartIoStoreHttpClient implements StoreHttpClient {
  DartIoStoreHttpClient({HttpClient? client})
      : _client = client ?? HttpClient();

  final HttpClient _client;

  @override
  Future<StoreHttpResponse> get(
    Uri uri, {
    Map<String, String>? headers,
  }) =>
      _send('GET', uri, headers: headers);

  @override
  Future<StoreHttpResponse> post(
    Uri uri, {
    Map<String, String>? headers,
    String? body,
  }) =>
      _send('POST', uri, headers: headers, body: body);

  Future<StoreHttpResponse> _send(
    String method,
    Uri uri, {
    Map<String, String>? headers,
    String? body,
  }) async {
    final request = await _client.openUrl(method, uri);
    headers?.forEach(request.headers.set);
    if (body != null) {
      final bytes = utf8.encode(body);
      request.headers.contentLength = bytes.length;
      request.add(bytes);
    }
    final response = await request.close();
    final responseBody = await response.transform(utf8.decoder).join();
    return StoreHttpResponse(
      statusCode: response.statusCode,
      body: responseBody,
    );
  }
}

/// Redacts credential-like substrings from API error text for findings.
String redactStoreApiError(String raw) {
  var text = raw.replaceAll(RegExp(r'\s+'), ' ').trim();
  text = text.replaceAll(
    RegExp(r'Bearer\s+[A-Za-z0-9._\-]+', caseSensitive: false),
    'Bearer [REDACTED]',
  );
  text = text.replaceAll(
    RegExp(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'),
    '[REDACTED_JWT]',
  );
  text = text.replaceAll(
    RegExp(
      r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----',
    ),
    '[REDACTED_PRIVATE_KEY]',
  );
  text = text.replaceAll(
    RegExp(r'"private_key"\s*:\s*"[^"]*"'),
    '"private_key":"[REDACTED]"',
  );
  text = text.replaceAll(
    RegExp(r'"access_token"\s*:\s*"[^"]*"'),
    '"access_token":"[REDACTED]"',
  );
  if (text.length > 240) {
    text = '${text.substring(0, 240)}…';
  }
  return text;
}
