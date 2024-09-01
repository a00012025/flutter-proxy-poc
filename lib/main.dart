import 'dart:io';
import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:pointycastle/export.dart' hide State;
import 'package:asn1lib/asn1lib.dart';
import 'dart:convert';

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

const supportedProtocols = ['h2', 'http/1.1'];

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
    // Load your CA's private key and certificate
    final caCertData = await rootBundle.load('assets/ca-cert.pem');
    final caKeyData = await rootBundle.load('assets/ca-key.pem');

    final caCert = caCertData.buffer.asUint8List();
    final caKey = caKeyData.buffer.asUint8List();

    final server = await ServerSocket.bind(InternetAddress.anyIPv4, 8080);
    print('TCP Proxy Server is running on port 8080');

    await for (Socket clientSocket in server) {
      _handleConnection(clientSocket, caCert, caKey);
    }
  }

  Future<void> _handleConnection(
      Socket clientSocket, Uint8List caCert, Uint8List caKey) async {
    clientSocket.listen((Uint8List data) async {
      String request = String.fromCharCodes(data);
      if (request.startsWith('CONNECT')) {
        // Parse the target host and port from the CONNECT request
        final targetInfo = request.split(' ')[1];
        final targetHost = targetInfo.split(':')[0];
        final targetPort = int.parse(targetInfo.split(':')[1]);

        // Respond with "200 Connection Established"
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

        // Dynamically generate server certificate for the target domain
        final securityContext =
            await generateSecurityContext(targetHost, caCert, caKey);

        // Start the TLS handshake and handle the connection in a new future
        SecureSocket secureClientSocket = await SecureSocket.secureServer(
            clientSocket, securityContext,
            supportedProtocols: supportedProtocols);

        // Handle the CONNECT method by establishing a connection to the target server
        await _handleTlsMitm(secureClientSocket, targetHost, targetPort);
      }
    });
  }

  Future<SecurityContext> generateSecurityContext(
      String domain, Uint8List caCert, Uint8List caKey) async {
    // Step 1: Generate RSA Key Pair
    final keyPair = generateKeyPair();

    // Step 2: Create CSR for the domain
    final csr = generateCSR(keyPair.privateKey, keyPair.publicKey, domain);

    // Step 3: Sign the CSR with the CA's private key
    final signedCert = signCSR(csr, caKey, caCert);

    // Step 4: Create a SecurityContext using the generated certificate
    final securityContext = SecurityContext();
    securityContext.useCertificateChainBytes(signedCert);
    securityContext.usePrivateKeyBytes(privateKeyToBytes(keyPair.privateKey));

    return securityContext;
  }

  Uint8List privateKeyToBytes(RSAPrivateKey privateKey) {
    var version =
        ASN1Integer(BigInt.from(0)); // PKCS#1 version (0 for private keys)
    var modulus = ASN1Integer(privateKey.n!);
    var publicExponent = ASN1Integer(privateKey.exponent!);
    var privateExponent = ASN1Integer(privateKey.privateExponent!);
    var prime1 = ASN1Integer(privateKey.p!);
    var prime2 = ASN1Integer(privateKey.q!);
    var exponent1 =
        ASN1Integer(privateKey.privateExponent! % (privateKey.p! - BigInt.one));
    var exponent2 =
        ASN1Integer(privateKey.privateExponent! % (privateKey.q! - BigInt.one));
    var coefficient = ASN1Integer(privateKey.q!.modInverse(privateKey.p!));

    var sequence = ASN1Sequence()
      ..add(version)
      ..add(modulus)
      ..add(publicExponent)
      ..add(privateExponent)
      ..add(prime1)
      ..add(prime2)
      ..add(exponent1)
      ..add(exponent2)
      ..add(coefficient);

    return sequence.encodedBytes;
  }

  AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> generateKeyPair() {
    final keyGen = KeyGenerator('RSA');
    keyGen.init(ParametersWithRandom(
        RSAKeyGeneratorParameters(BigInt.from(65537), 2048, 12),
        SecureRandom('Fortuna')
          ..seed(KeyParameter(
              Uint8List.fromList(List<int>.generate(32, (_) => 42))))));
    final pair = keyGen.generateKeyPair();
    return AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(
        pair.publicKey as RSAPublicKey, pair.privateKey as RSAPrivateKey);
  }

  ASN1Object generateCSR(
      RSAPrivateKey privateKey, RSAPublicKey publicKey, String commonName) {
    final asn1 = ASN1Sequence();

    final version = ASN1Integer(BigInt.from(0)); // Version 1
    asn1.add(version);

    final subject = ASN1Sequence();
    subject.add(ASN1Set()
      ..add(ASN1Sequence()
        ..add(ASN1ObjectIdentifier.fromComponentString('2.5.4.3'))
        ..add(ASN1UTF8String(commonName))));
    asn1.add(subject);

    final publicKeyInfo = ASN1Sequence();
    publicKeyInfo.add(ASN1Sequence()
      ..add(ASN1ObjectIdentifier.fromComponentString('1.2.840.113549.1.1.1'))
      ..add(ASN1Null()));
    publicKeyInfo.add(
        ASN1BitString(Uint8List.fromList(bigIntToBytes(publicKey.modulus!))));
    asn1.add(publicKeyInfo);

    // Sign the CSR
    final signer = Signer('SHA-256/RSA');
    signer.init(true, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    final signature = signer.generateSignature(asn1.encodedBytes);

    asn1.add(ASN1Sequence()
      ..add(ASN1ObjectIdentifier.fromComponentString('1.2.840.113549.1.1.1'))
      ..add(ASN1Null()));
    asn1.add(
        ASN1BitString(Uint8List.fromList((signature as RSASignature).bytes)));

    return asn1;
  }

  Uint8List bigIntToBytes(BigInt number) {
    // Handle the special case for zero
    if (number == BigInt.zero) {
      return Uint8List(1)..[0] = 0;
    }

    // Determine the number of bytes required
    int numBytes = (number.bitLength + 7) ~/ 8;
    var result = Uint8List(numBytes);
    var temp = number;

    for (int i = 0; i < numBytes; i++) {
      result[numBytes - i - 1] = (temp & BigInt.from(0xff)).toInt();
      temp = temp >> 8;
    }

    return result;
  }

  Uint8List signCSR(ASN1Object csr, Uint8List caPrivateKey, Uint8List caCert) {
    // Implement the signing logic here (simplified)
    final signer = Signer('SHA-256/RSA');
    signer.init(
        true, PrivateKeyParameter<RSAPrivateKey>(loadPrivateKey(caPrivateKey)));
    return (signer.generateSignature(csr.encodedBytes) as RSASignature).bytes;
  }

  RSAPrivateKey loadPrivateKey(Uint8List keyData) {
    // Step 1: Decode the PEM format if needed
    String pem = utf8.decode(keyData);
    pem = pem.replaceAll('-----BEGIN PRIVATE KEY-----', '');
    pem = pem.replaceAll('-----END PRIVATE KEY-----', '');
    pem = pem.replaceAll('\n', '');
    Uint8List derData = base64.decode(pem);

    // Step 2: Parse the ASN.1 structure
    ASN1Parser asn1Parser = ASN1Parser(derData);
    ASN1Sequence topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    // Step 3: Check the structure and navigate correctly
    int currentIndex = 0;

    if (topLevelSeq.elements[currentIndex] is ASN1Integer) {
      // PKCS#1 format starts with an Integer (version)
      currentIndex++; // Skip the version
    } else if (topLevelSeq.elements[currentIndex] is ASN1Sequence) {
      // PKCS#8 format starts with a sequence
      ASN1Sequence algorithmSeq =
          topLevelSeq.elements[currentIndex++] as ASN1Sequence;
      ASN1ObjectIdentifier oid =
          algorithmSeq.elements[0] as ASN1ObjectIdentifier;
      print("Algorithm OID: ${oid.identifier}");
      // The actual key data is in the next element, which is a bit string
      ASN1BitString bitString =
          topLevelSeq.elements[currentIndex++] as ASN1BitString;
      asn1Parser = ASN1Parser(bitString.encodedBytes);
      topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
      currentIndex = 0;
    }

    // Now we should be in the correct sequence for key components
    BigInt modulus =
        (topLevelSeq.elements[currentIndex++] as ASN1Integer).valueAsBigInteger;
    BigInt publicExponent =
        (topLevelSeq.elements[currentIndex++] as ASN1Integer).valueAsBigInteger;
    BigInt privateExponent =
        (topLevelSeq.elements[currentIndex++] as ASN1Integer).valueAsBigInteger;
    BigInt p =
        (topLevelSeq.elements[currentIndex++] as ASN1Integer).valueAsBigInteger;
    BigInt q =
        (topLevelSeq.elements[currentIndex++] as ASN1Integer).valueAsBigInteger;
    BigInt exp1 =
        (topLevelSeq.elements[currentIndex++] as ASN1Integer).valueAsBigInteger;
    BigInt exp2 =
        (topLevelSeq.elements[currentIndex++] as ASN1Integer).valueAsBigInteger;
    BigInt coeff =
        (topLevelSeq.elements[currentIndex++] as ASN1Integer).valueAsBigInteger;

    // Step 4: Create and return the RSAPrivateKey object
    return RSAPrivateKey(modulus, privateExponent, p, q);
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
