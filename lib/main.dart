import 'dart:io';
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      home: ProxyDemo(),
    );
  }
}

class ProxyDemo extends StatefulWidget {
  const ProxyDemo({super.key});

  @override
  _ProxyDemoState createState() => _ProxyDemoState();
}

class _ProxyDemoState extends State<ProxyDemo> {
  HttpServer? _server;

  @override
  void initState() {
    super.initState();
    startProxy();
  }

  @override
  void dispose() {
    _server?.close();
    super.dispose();
  }

  Future<void> startProxy() async {
    try {
      // Load the key from the assets and write it to a temporary file
      final keyData = await rootBundle.load('assets/harry-proxy.key');
      final tempDir = await getApplicationDocumentsDirectory();
      final keyFile = File('${tempDir.path}/harry-proxy.key');
      await keyFile.writeAsBytes(keyData.buffer.asUint8List());

      // Load the certificate from the assets and write it to a temporary file
      final certData = await rootBundle.load('assets/harry-proxy.crt');
      final certFile = File('${tempDir.path}/harry-proxy.crt');
      await certFile.writeAsBytes(certData.buffer.asUint8List());

      // Loading the certificate and key
      final securityContext = SecurityContext()
        ..useCertificateChain(certFile.path)
        ..usePrivateKey(keyFile.path);

      // Bind the server
      _server = await HttpServer.bindSecure(
        InternetAddress.anyIPv4,
        8080,
        securityContext,
      );

      print('Proxy server running on https://localhost:8080');

      await for (HttpRequest request in _server!) {
        // Extract and log the requested URL
        final uri = request.uri.toString();
        print('Intercepted URL: $uri');

        // Forward the request to the intended server
        final HttpClient httpClient = HttpClient(context: securityContext);
        final HttpClientRequest clientRequest =
            await httpClient.openUrl(request.method, request.uri);

        // Copy headers
        request.headers.forEach((name, values) {
          for (var value in values) {
            clientRequest.headers.add(name, value);
          }
        });

        // Copy body if it exists
        if (request.contentLength > 0) {
          await request.pipe(clientRequest as StreamConsumer<Uint8List>);
        }

        // Get response from the server
        final HttpClientResponse clientResponse = await clientRequest.close();

        // Send the response back to the client
        request.response.statusCode = clientResponse.statusCode;
        clientResponse.headers.forEach((name, values) {
          for (var value in values) {
            request.response.headers.add(name, value);
          }
        });
        await clientResponse.pipe(request.response);
      }
    } catch (e) {
      print('Failed to start proxy: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('HTTPS Proxy Demo'),
      ),
      body: const Center(
        child: Text('Proxy is running. Check console for intercepted URLs.'),
      ),
    );
  }
}
