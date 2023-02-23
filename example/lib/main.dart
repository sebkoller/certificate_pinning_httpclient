import 'package:certificate_pinning_httpclient/certificate_pinning_httpclient.dart';
import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:flutter/material.dart';
import 'package:http/io_client.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
      theme: ThemeData(
        primarySwatch: Colors.blue,
      ),
      home: const MyHomePage(title: 'Certificate Pinning Demo'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  int _httpStatus = 0;
  int _dioStatus = 0;
  String _httpError = "";
  String _dioError = "";
  static const String exampleComSpki =
      "Xs+pjRp23QkmXeH31KEAjM1aWvxpHT6vYy+q2ltqtaM="; // might be out-of-date

  final _http = IOClient(CertificatePinningHttpClient([exampleComSpki]));
  final _dio = Dio();

  _MyHomePageState() {
    (_dio.httpClientAdapter as IOHttpClientAdapter).onHttpClientCreate =
        (client) => CertificatePinningHttpClient([exampleComSpki]);
  }

  Future<void> _makeHttpCall(String url) async {
    int httpStatus = -1;
    int dioStatus = -1;
    String? httpError;
    String? dioError;

    try {
      httpStatus = (await _http.get(Uri.parse(url))).statusCode;
    } catch (err) {
      httpError = err.toString();
    }

    try {
      dioStatus = (await _dio.get(url)).statusCode!;
    } catch (err) {
      dioError = err.toString();
    }

    setState(() {
      _httpStatus = httpStatus;
      _dioStatus = dioStatus;
      _httpError = httpError ?? "";
      _dioError = dioError ?? "";
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            TextButton(
              onPressed: () {
                _makeHttpCall("https://example.com");
              },
              child: const Text("GET example.com"),
            ),
            TextButton(
              onPressed: () {
                _makeHttpCall("https://pub.dev");
              },
              child: const Text("GET pub.dev (with invalid pins)"),
            ),
            const SizedBox(height: 20),
            Text('Http status from http client: $_httpStatus'),
            Text('Http status from dio client: $_dioStatus'),
            const SizedBox(height: 20),
            if (_httpError.isNotEmpty)
              Text("Error from http client: $_httpError"),
            const SizedBox(height: 20),
            if (_dioError.isNotEmpty) Text("Error from dio client: $_dioError"),
          ],
        ),
      ),
    );
  }
}
