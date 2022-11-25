# certificate\_pinning\_httpclient

An implementation of an HttpClient with certificate pinning.

Pinning is done against SPKI (subject public key info) SHA-256 hashes.
The client will download the certificates via a MethodChannel and cache them.
All certificates with a matching SPKI hash will be used with a SecurityContext.

## Usage

The client will log the SPKI hash of each certificate in the chain. Use this to get your hash.
You can also get the hash with GnuTLS: `gnutls-cli --print-cert example.com` (look for the Public Key PIN).

```dart
import 'package:certificate_pinning_httpclient/certificate_pinning_httpclient.dart';

// with http
final client = IOClient(CertificatePinningHttpClient(
        ["S4kZuhQQ1DPcMOCYFQXD0gG+UW0zmyVx6roNWpRl65I="]));

// with Dio
final _dio = Dio();
(_dio.httpClientAdapter as DefaultHttpClientAdapter).onHttpClientCreate =
    (client) => CertificatePinningHttpClient(
        ["S4kZuhQQ1DPcMOCYFQXD0gG+UW0zmyVx6roNWpRl65I="]);

```

Disable logs for release builds:

```dart
import 'package:logger/logger.dart';

Logger.level = kDebugMode ? Level.debug : Level.nothing;
```

## Credits

https://github.com/approov/approov-service-flutter-httpclient
