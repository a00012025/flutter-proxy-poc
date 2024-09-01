import 'dart:io';
import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

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

const supportedProtocols = ['http/1.1', 'h2'];

class _ProxyDemoState extends State<ProxyDemo> {
  HttpServer? _server;
  SecurityContext? securityContext;

  @override
  void initState() {
    super.initState();
    startTcpProxy();
  }

  @override
  void dispose() {
    _server?.close();
    super.dispose();
  }

  Future<void> startTcpProxy() async {
    // Upgrade the socket to a SecureSocket (Server-side TLS)
    final p12Data = await rootBundle.load('assets/harry-local.p12');
    final p12Bytes = p12Data.buffer.asUint8List();
    securityContext = SecurityContext()
      ..useCertificateChainBytes(p12Bytes, password: 'abc')
      ..usePrivateKeyBytes(p12Bytes, password: 'abc')
      ..setAlpnProtocols(supportedProtocols, true);

    final server = await ServerSocket.bind(InternetAddress.anyIPv4, 8080);
    print('TCP Proxy Server is running on port 8080');

    await for (Socket clientSocket in server) {
      _handleConnection(clientSocket);
    }
  }

  Future<void> _handleConnection(Socket clientSocket) async {
    clientSocket.listen((Uint8List data) async {
      String request = String.fromCharCodes(data);
      if (request.startsWith('CONNECT')) {
        // Parse the target host and port from the CONNECT request
        final targetInfo = request.split(' ')[1];
        final targetHost = targetInfo.split(':')[0];
        final targetPort = int.parse(targetInfo.split(':')[1]);

        // Respond with "200 Connection Established"
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

        // Start the TLS handshake and handle the connection in a new future
        SecureSocket secureClientSocket = await SecureSocket.secureServer(
            clientSocket, securityContext,
            supportedProtocols: supportedProtocols);

        // Handle the CONNECT method by establishing a connection to the target server
        await _handleTlsMitm(secureClientSocket, targetHost, targetPort);
      }
    });
  }

  Future<void> _handleTlsMitm(
      SecureSocket clientSocket, String targetHost, int targetPort) async {
    try {
      // Establish a TLS connection to the target server
      final SecureSocket targetSocket = await SecureSocket.connect(
        targetHost,
        targetPort,
        context: SecurityContext.defaultContext,
        supportedProtocols: supportedProtocols,
      );

      // Forward data from the client to the target server
      clientSocket.listen(
        (data) {
          print('Received data from client: ${String.fromCharCodes(data)}');
          targetSocket.add(data);
        },
        onError: (error) {
          print('Error in client socket: $error');
          targetSocket.destroy();
        },
        onDone: () {
          print('Client socket closed.');
          targetSocket.destroy();
        },
        cancelOnError: true,
      );

      // Forward data from the target server to the client
      targetSocket.listen(
        (data) {
          print('Received data from target: ${String.fromCharCodes(data)}');
          clientSocket.add(data);
        },
        onError: (error) {
          print('Error in target socket: $error');
          clientSocket.destroy();
        },
        onDone: () {
          print('Target socket closed.');
          clientSocket.destroy();
        },
        cancelOnError: true,
      );
    } catch (e) {
      print('Error during MITM TLS handling: $e');
      clientSocket.destroy();
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
