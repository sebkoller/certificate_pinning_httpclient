import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:asn1lib/asn1lib.dart';
import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:logger/logger.dart';
import 'package:pem/pem.dart';

final Logger _log = Logger();

class _CertificatePinningService {
  // logging tag
  static const String _tag = "CertificatePinningHttpClient";

  static const MethodChannel _channel =
      MethodChannel('certificate_pinning_httpclient');

  static final Map<String, List<Uint8List>?> _hostCertificates =
      <String, List<Uint8List>?>{};

  /// Retrieves the certificates in the chain for the specified host. These are obtained at the platform level and we
  /// cache them so subsequent requests don't require another probe.
  ///
  /// @param host is the URL specifying the host for which to retrieve the certificates (e.g. "www.example.com")
  /// @return a list of certificates (each as a Uint8list) for the host specified in the URL, null if an error occurred,
  /// or an empty list if no suitable certificates are available.
  static Future<List<Uint8List>?> _getHostCertificates(Uri url) async {
    if (_hostCertificates[url.host] == null) {
      try {
        final arguments = <String, String>{
          "url": url.toString(),
        };
        final List<Object?>? fetchedHostCertificates =
            await _channel.invokeMethod('fetchHostCertificates', arguments);
        if (fetchedHostCertificates?.isNotEmpty ?? false) {
          // cache the obtained host certificates
          _hostCertificates[url.host] = fetchedHostCertificates
              ?.map((c) => c as Uint8List?)
              .whereType<Uint8List>()
              .toList(growable: false);
        }
      } catch (err) {
        _log.d("$_tag: Error when fetching host certificates: $err");
        // do not throw an exception, but let the function return null
      }
    }
    return _hostCertificates[url.host];
  }

  /// Gets all certificates of a host that match the pins for that host. A match is determined by comparing
  /// the certificate's SPKI's SHA256 digest with the list of pins. We firstly get the certificate chain for the
  /// host (which may have been previously cached) and then we restrict it to those corresponding to pinned
  /// certificates.
  ///
  /// @param url of the host that is being pinned
  /// @param validPins is the set of pins for the host
  /// @return a list of host certificates that match the valid pins
  static Future<List<Uint8List>> _hostPinCertificates(
      Uri url, Set<String> validPins) async {
    // get certificates for host
    final hostCertificates =
        await _CertificatePinningService._getHostCertificates(url);
    if (hostCertificates == null) {
      // if there are none then we return an empty list, which will cause a failure when we try and connect
      _log.d("$_tag: Cannot get certificates for $url");
      return [];
    }

    // collect only those certificates for pinning that match valid pin
    final info = StringBuffer("Certificate chain for $url: ");
    bool isFirst = true;
    final List<Uint8List> hostPinCerts = [];
    for (final cert in hostCertificates) {
      final Uint8List serverSpkiSha256Digest =
          Uint8List.fromList(_spkiSha256Digest(cert).bytes);
      if (!isFirst) info.write(", ");
      isFirst = false;
      info.write(base64.encode(serverSpkiSha256Digest));
      for (final pin in validPins) {
        if (_listEquals(base64.decode(pin), serverSpkiSha256Digest)) {
          hostPinCerts.add(cert);
          info.write(" pinned");
        }
      }
    }
    _log.d("$_tag: $info");
    return hostPinCerts;
  }

  /// Create a security context that enforces pinning to host certificates whose SPKI SHA256 digest match an
  /// pin. If no certificates match, the security context does not contain any host certificates and creating a TLS
  /// connection to the host will fail. These certificates that match a pin are set to the trusted certificates for the
  /// security context so that connections are restricted to ensure one of those certificates is present.
  ///
  /// @param url of the host that is being pinned
  /// @param validPins is the set of pins for the host
  /// @return a security context that enforces pinning by using the host certificates that match the pins
  static Future<SecurityContext> _pinnedSecurityContext(
      Uri url, Set<String> validPins) async {
    // determine the list of X.509 ASN.1 DER host certificates that match any pins for the host - if this
    // returns an empty list then nothing will be trusted
    final List<Uint8List> pinCerts =
        await _CertificatePinningService._hostPinCertificates(url, validPins);

    // add the certificates to create the security context of trusted certs
    final securityContext = SecurityContext();
    for (final pinCert in pinCerts) {
      final pemCertificate = PemCodec(PemLabel.certificate).encode(pinCert);
      final Uint8List pemCertificatesBytes =
          const AsciiEncoder().convert(pemCertificate);
      securityContext.setTrustedCertificatesBytes(pemCertificatesBytes);
    }
    _log.d(
        "$_tag: Pinned security context with ${pinCerts.length} trusted certs, from ${validPins.length} possible pins");
    return securityContext;
  }

  static Future<void> _removeCertificates(String host) async {
    _hostCertificates[host] = null;
  }

  /// Computes the SHA256 digest of the Subject Public Key Info (SPKI) of an ASN1.DER encoded certificate.
  ///
  /// @param certificate for which to compute the SPKI digest
  /// @return the SHA256 digest of the certificate's SPKI
  static Digest _spkiSha256Digest(Uint8List certificate) {
    final asn1Parser = ASN1Parser(certificate);
    final signedCert = asn1Parser.nextObject() as ASN1Sequence;
    final cert = signedCert.elements[0] as ASN1Sequence;
    final spki = cert.elements[6] as ASN1Sequence;
    final spkiDigest = sha256.convert(spki.encodedBytes);
    return spkiDigest;
  }

  // copied from https://pub.dev/packages/collection
  static bool _listEquals<E>(List<E>? list1, List<E>? list2) {
    if (identical(list1, list2)) return true;
    if (list1 == null || list2 == null) return false;
    final length = list1.length;
    if (length != list2.length) return false;
    for (var i = 0; i < length; i++) {
      if (list1[i] != list2[i]) return false;
    }
    return true;
  }
}

class _Credential {
  final Uri url;
  final String realm;
  final HttpClientCredentials credentials;

  _Credential(this.url, this.realm, this.credentials);
}

class _ProxyCredential {
  final String host;
  final int port;
  final String realm;
  final HttpClientCredentials credentials;

  _ProxyCredential(this.host, this.port, this.realm, this.credentials);
}

/// An implementation of Dart's HttpClient with certificate pinning against SPKI hashes.
///
class CertificatePinningHttpClient implements HttpClient {
  // logging tag
  static const String _tag = "CertificatePinningHttpClient";

  // list of SPKI hashes
  final Set<String> _validPins;

  // internal HttpClient delegate, will be rebuilt if pinning fails (or pins change). It is not set to a pinned
  // HttpClient initially, but this is just used to hold any state updates that might occur before a connection
  // request forces a pinned HttpClient to be used.
  HttpClient _delegatePinnedHttpClient = HttpClient();

  // the host to which the delegate pinned HttpClient delegate is connected and, optionally, pinning. Used to detect when to
  // re-create the delegate pinned HttpClient.
  String? _connectedHost;

  // indicates whether the HttpClient has been closed by calling close().
  bool _isClosed = false;

  Completer<HttpClient>? _createClientCompleter;

  // state required to implement getters and setters required by the HttpClient interface
  Future<bool> Function(Uri url, String scheme, String? realm)? _authenticate;
  Future<ConnectionTask<Socket>> Function(
      Uri url, String? proxyHost, int? proxyPort)? _connectionFactory;
  void Function(String line)? _keyLog;
  final List<_Credential> _credentials = [];
  String Function(Uri url)? _findProxy;
  Future<bool> Function(String host, int port, String scheme, String? realm)?
      _authenticateProxy;
  final List<_ProxyCredential> _proxyCredentials = [];
  bool Function(X509Certificate cert, String host, int port)?
      _badCertificateCallback;

  /// Pinning failure callback function for the badCertificateCallback of HttpClient. This is called if the pinning
  /// certificate check failed, which can indicate a certificate update on the server or a Man-in-the-Middle (MitM)
  /// attack. It invalidates the certificates for the given host so they will be refreshed and the communication with
  /// the server can be re-established for the case of a certificate update. Returns false to prevent the request to
  /// be sent for the case of a MitM attack.
  ///
  /// @param cert is the certificate which could not be authenticated
  /// @param host is the host name of the server to which the request is being sent
  /// @param port is the port of the server
  bool _pinningFailureCallback(X509Certificate cert, String host, int port) {
    final Function(X509Certificate cert, String host, int port)?
        badCertificateCallback = _badCertificateCallback;
    if (badCertificateCallback != null) {
      // call the user defined function for its side effects only (as we are going to reject anyway)
      badCertificateCallback(cert, host, port);
    }

    // reset host certificates and delegate pinned HttpClient connected host to force them to be recreated
    _log.d("$_tag: Pinning failure callback for $host");
    _CertificatePinningService._removeCertificates(host);
    _connectedHost = null;
    return false;
  }

  /// Create an HTTP client with pinning enabled. The state for the new
  /// HTTP client is copied from the current delegate.
  ///
  /// @param url for which to set up pinning
  /// @return the new HTTP client
  Future<HttpClient> _createPinnedHttpClient(Uri url) async {
    final completer = Completer<HttpClient>();
    _createClientCompleter = completer;

    // construct a new http client
    HttpClient? newHttpClient;
    if (_validPins.isEmpty) {
      // if there are no pins then we can just use a standard http client
      newHttpClient = HttpClient();
    } else {
      final securityContext =
          await _CertificatePinningService._pinnedSecurityContext(
              url, _validPins);
      newHttpClient = HttpClient(context: securityContext);
    }

    // remember the connected host so we don't have to repeat this for connections to the same host
    _connectedHost = url.host;

    // copy state from old HttpClient to the new one, including state held on this class which cannot be retrieved
    final HttpClient oldHttpClient = _delegatePinnedHttpClient;
    newHttpClient.idleTimeout = oldHttpClient.idleTimeout;
    newHttpClient.userAgent = oldHttpClient.userAgent;
    newHttpClient.connectionTimeout = oldHttpClient.connectionTimeout;
    newHttpClient.maxConnectionsPerHost = oldHttpClient.maxConnectionsPerHost;
    newHttpClient.autoUncompress = oldHttpClient.autoUncompress;
    newHttpClient.authenticate = _authenticate;
    newHttpClient.connectionFactory = _connectionFactory;
    newHttpClient.keyLog = _keyLog;
    for (final credential in _credentials) {
      newHttpClient.addCredentials(
          credential.url, credential.realm, credential.credentials);
    }
    newHttpClient.findProxy = _findProxy;
    newHttpClient.authenticateProxy = _authenticateProxy;
    for (final proxyCredential in _proxyCredentials) {
      newHttpClient.addProxyCredentials(
          proxyCredential.host,
          proxyCredential.port,
          proxyCredential.realm,
          proxyCredential.credentials);
    }
    newHttpClient.badCertificateCallback = _pinningFailureCallback;

    completer.complete(newHttpClient);

    // provide the new http client with a pinned security context
    return newHttpClient;
  }

  // Constructor for a Certificate Pinning HttpClient.
  //
  // @param pins is a list of SPKI hashes
  CertificatePinningHttpClient(List<String> spkiHashes)
      : _validPins = spkiHashes.toSet(),
        super();

  @override
  Future<HttpClientRequest> open(
      String method, String host, int port, String path) async {
    // if already closed then just delegate
    if (_isClosed) {
      return _delegatePinnedHttpClient.open(method, host, port, path);
    }

    if(_createClientCompleter != null) {
      await _createClientCompleter!.future;
    }

    // if we have an active connection to a different host we need to tear down the delegate
    // pinned HttpClient and create a new one with the correct pinning
    if (_connectedHost != host) {
      final url = Uri(scheme: "https", host: host, port: port, path: path);
      final httpClient = await _createPinnedHttpClient(url);
      _delegatePinnedHttpClient.close();
      _delegatePinnedHttpClient = httpClient;
    }

    // delegate the open operation to the pinned http client
    return _delegatePinnedHttpClient.open(method, host, port, path);
  }

  @override
  Future<HttpClientRequest> openUrl(String method, Uri url) async {
    // if already closed then just delegate
    if (_isClosed) {
      return _delegatePinnedHttpClient.openUrl(method, url);
    }

    if(_createClientCompleter != null) {
      await _createClientCompleter!.future;
    }

    // if we have an active connection to a different host we need to tear down the delegate
    // pinned HttpClient and create a new one with the correct pinning
    if (_connectedHost != url.host) {
      final httpClient = await _createPinnedHttpClient(url);
      _delegatePinnedHttpClient.close();
      _delegatePinnedHttpClient = httpClient;
    }

    // delegate the open operation to the pinned http client
    return _delegatePinnedHttpClient.openUrl(method, url);
  }

  @override
  Future<HttpClientRequest> get(String host, int port, String path) =>
      open("get", host, port, path);

  @override
  Future<HttpClientRequest> getUrl(Uri url) => openUrl("get", url);

  @override
  Future<HttpClientRequest> post(String host, int port, String path) =>
      open("post", host, port, path);

  @override
  Future<HttpClientRequest> postUrl(Uri url) => openUrl("post", url);

  @override
  Future<HttpClientRequest> put(String host, int port, String path) =>
      open("put", host, port, path);

  @override
  Future<HttpClientRequest> putUrl(Uri url) => openUrl("put", url);

  @override
  Future<HttpClientRequest> delete(String host, int port, String path) =>
      open("delete", host, port, path);

  @override
  Future<HttpClientRequest> deleteUrl(Uri url) => openUrl("delete", url);

  @override
  Future<HttpClientRequest> head(String host, int port, String path) =>
      open("head", host, port, path);

  @override
  Future<HttpClientRequest> headUrl(Uri url) => openUrl("head", url);

  @override
  Future<HttpClientRequest> patch(String host, int port, String path) =>
      open("patch", host, port, path);

  @override
  Future<HttpClientRequest> patchUrl(Uri url) => openUrl("patch", url);

  @override
  set idleTimeout(Duration timeout) =>
      _delegatePinnedHttpClient.idleTimeout = timeout;

  @override
  Duration get idleTimeout => _delegatePinnedHttpClient.idleTimeout;

  @override
  set connectionTimeout(Duration? timeout) =>
      _delegatePinnedHttpClient.connectionTimeout = timeout;

  @override
  Duration? get connectionTimeout =>
      _delegatePinnedHttpClient.connectionTimeout;

  @override
  set maxConnectionsPerHost(int? maxConnections) =>
      _delegatePinnedHttpClient.maxConnectionsPerHost = maxConnections;

  @override
  int? get maxConnectionsPerHost =>
      _delegatePinnedHttpClient.maxConnectionsPerHost;

  @override
  set autoUncompress(bool autoUncompress) =>
      _delegatePinnedHttpClient.autoUncompress = autoUncompress;

  @override
  bool get autoUncompress => _delegatePinnedHttpClient.autoUncompress;

  @override
  set userAgent(String? userAgent) =>
      _delegatePinnedHttpClient.userAgent = userAgent;

  @override
  String? get userAgent => _delegatePinnedHttpClient.userAgent;

  @override
  set authenticate(
      Future<bool> Function(Uri url, String scheme, String? realm)? f) {
    _authenticate = f;
    _delegatePinnedHttpClient.authenticate = f;
  }

  @override
  set connectionFactory(
      Future<ConnectionTask<Socket>> Function(
              Uri url, String? proxyHost, int? proxyPort)?
          f) {
    _connectionFactory = f;
    _delegatePinnedHttpClient.connectionFactory = f;
  }

  @override
  set keyLog(void Function(String line)? f) {
    _keyLog = f;
    _delegatePinnedHttpClient.keyLog = f;
  }

  @override
  void addCredentials(
      Uri url, String realm, HttpClientCredentials credentials) {
    _credentials.add(_Credential(url, realm, credentials));
    _delegatePinnedHttpClient.addCredentials(url, realm, credentials);
  }

  @override
  set findProxy(String Function(Uri url)? f) {
    _findProxy = f;
    _delegatePinnedHttpClient.findProxy = f;
  }

  @override
  set authenticateProxy(
      Future<bool> Function(
              String host, int port, String scheme, String? realm)?
          f) {
    _authenticateProxy = f;
    _delegatePinnedHttpClient.authenticateProxy = f;
  }

  @override
  void addProxyCredentials(
      String host, int port, String realm, HttpClientCredentials credentials) {
    _proxyCredentials.add(_ProxyCredential(host, port, realm, credentials));
    _delegatePinnedHttpClient.addProxyCredentials(
        host, port, realm, credentials);
  }

  /// This callback will be invoked, but CertificatePinningHttpClient will not use the return value.
  @override
  set badCertificateCallback(
      bool Function(X509Certificate cert, String host, int port)? callback) {
    _badCertificateCallback = callback;
  }

  @override
  void close({bool force = false}) {
    _delegatePinnedHttpClient.close(force: force);
    _isClosed = true;
  }
}
