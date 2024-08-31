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
      final certDir = await getApplicationDocumentsDirectory();

      // Load the certificate and key from assets
      final certData = await rootBundle.load('assets/harry-proxy.crt');
      final keyData = await rootBundle.load('assets/harry-proxy.key');

      final certPath = '${certDir.path}/harry-proxy.crt';
      final keyPath = '${certDir.path}/harry-proxy.key';

      // Write cert and key to file
      final certFile = File(certPath);
      final keyFile = File(keyPath);
      await certFile.writeAsBytes(certData.buffer.asUint8List());
      await keyFile.writeAsBytes(keyData.buffer.asUint8List());

      // Setup SecurityContext
      final securityContext = SecurityContext()
        ..useCertificateChain(certPath)
        ..usePrivateKey(keyPath);

      // Start the proxy server
      _server = await HttpServer.bind(InternetAddress.anyIPv4, 8080);

      print(
          'Proxy server running on http://${_server!.address.address}:${_server!.port}');

      await for (HttpRequest request in _server!) {
        handleRequest(request, securityContext);
      }
    } catch (e) {
      print('Failed to start proxy: $e');
    }
  }

  void handleRequest(
      HttpRequest request, SecurityContext securityContext) async {
    try {
      final uri = request.uri;
      print('Intercepted URL: $uri');

      // Create a new HttpClient to forward the request
      final httpClient = HttpClient(context: securityContext);
      httpClient.badCertificateCallback = (cert, host, port) => true;

      final isConnect = request.method == 'CONNECT';
      final targetUri =
          isConnect ? Uri.parse('https://${uri.toString()}') : uri;
      print('Target URI: $targetUri'); // Add this line for debugging

      if (isConnect) {
        // Handle CONNECT method for HTTPS
        final socket = await request.response.detachSocket();

        // Check if the host is not empty before attempting to connect
        if (targetUri.host.isNotEmpty) {
          final secureSocket = await SecureSocket.connect(
            targetUri.host,
            targetUri.port,
            context: securityContext,
            onBadCertificate: (cert) => true,
          );

          await socket.addStream(secureSocket);
          await secureSocket.addStream(socket);

          final clientRequest = await httpClient.getUrl(targetUri);
          final clientResponse = await clientRequest.close();

          await secureSocket.addStream(clientResponse);
          await socket.addStream(secureSocket);
        } else {
          print('Error: Empty host in CONNECT request');
          socket.destroy();
        }
      } else {
        // Handle regular HTTP requests
        final clientRequest =
            await httpClient.openUrl(request.method, targetUri);

        // Copy the headers, excluding Content-Length
        request.headers.forEach((name, values) {
          if (name.toLowerCase() != 'content-length') {
            for (var value in values) {
              clientRequest.headers.add(name, value);
            }
          } else {
            print('Skipping Content-Length header. Value: ${values.first}');
          }
        });

        // Copy the body and calculate new content length
        List<int> bodyBytes = [];
        await for (var chunk in request) {
          bodyBytes.addAll(chunk);
        }

        if (bodyBytes.isNotEmpty) {
          clientRequest.contentLength = bodyBytes.length;
          clientRequest.add(bodyBytes);
        }

        await clientRequest.close();

        final clientResponse = await clientRequest.close();

        // Set the response headers
        request.response.statusCode = clientResponse.statusCode;
        clientResponse.headers.forEach((name, values) {
          for (var value in values) {
            request.response.headers.add(name, value);
          }
        });

        // Pipe the response back to the client
        await request.response.addStream(clientResponse);
      }
    } catch (e, s) {
      print('Error handling request: $e , $s');
      // request.response.statusCode = HttpStatus.internalServerError;
      await request.response.close();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('HTTPS Proxy Demo'),
      ),
      body: Center(
        child: Text('Proxy is running. Check console for intercepted URLs.'),
      ),
    );
  }
}
