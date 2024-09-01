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
            await generateSecurityContext(targetHost, caKey, caCert);

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
      String domain, Uint8List caKey, Uint8List caCert) async {
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

  Uint8List signCSR(ASN1Object csr, Uint8List caPrivateKey, Uint8List caCert) {
    final signer = Signer('SHA-256/RSA');
    signer.init(
        true, PrivateKeyParameter<RSAPrivateKey>(loadPrivateKey(caPrivateKey)));

    // Generate the signature for the CSR
    final signature =
        signer.generateSignature(csr.encodedBytes) as RSASignature;

    // Create a new ASN.1 sequence to hold the signed certificate
    final signedCert = ASN1Sequence();

    // Add the original CSR
    signedCert.add(csr);

    // Add the signature algorithm identifier
    final sigAlgId = ASN1Sequence();
    sigAlgId.add(ASN1ObjectIdentifier.fromComponentString(
        '1.2.840.113549.1.1.11')); // sha256WithRSAEncryption OID
    sigAlgId.add(ASN1Null());
    signedCert.add(sigAlgId);

    // Add the signature
    final signatureBitString =
        ASN1BitString(Uint8List.fromList(signature.bytes));
    signedCert.add(signatureBitString);

    return signedCert.encodedBytes;
  }

  Uint8List privateKeyToBytes(RSAPrivateKey privateKey) {
    var version =
        ASN1Integer(BigInt.from(0)); // PKCS#8 version (0 for private keys)
    var privateKeyAlgorithm = ASN1Sequence()
      ..add(ASN1ObjectIdentifier.fromComponentString(
          '1.2.840.113549.1.1.1')) // rsaEncryption OID
      ..add(ASN1Null());

    var privateKeySequence = ASN1Sequence()
      ..add(ASN1Integer(BigInt.from(0))) // PKCS#1 version (0 for private keys)
      ..add(ASN1Integer(privateKey.n!))
      ..add(ASN1Integer(privateKey.exponent!))
      ..add(ASN1Integer(privateKey.privateExponent!))
      ..add(ASN1Integer(privateKey.p!))
      ..add(ASN1Integer(privateKey.q!))
      ..add(ASN1Integer(
          privateKey.privateExponent! % (privateKey.p! - BigInt.one)))
      ..add(ASN1Integer(
          privateKey.privateExponent! % (privateKey.q! - BigInt.one)))
      ..add(ASN1Integer(privateKey.q!.modInverse(privateKey.p!)));

    var privateKeyOctetString =
        ASN1OctetString(privateKeySequence.encodedBytes);

    var sequence = ASN1Sequence()
      ..add(version)
      ..add(privateKeyAlgorithm)
      ..add(privateKeyOctetString);

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
    // Step 1: Create the main ASN.1 sequence
    final asn1 = ASN1Sequence();

    // Step 2: Add the version
    final version = ASN1Integer(BigInt.from(0)); // Version 1
    asn1.add(version);

    // Step 3: Add the subject information (Common Name)
    final subject = ASN1Sequence();
    subject.add(ASN1Set()
      ..add(ASN1Sequence()
        ..add(ASN1ObjectIdentifier.fromComponentString('2.5.4.3'))
        ..add(ASN1UTF8String(commonName))));
    asn1.add(subject);

    // Step 4: Add the public key information
    final publicKeyInfo = ASN1Sequence();
    publicKeyInfo.add(ASN1Sequence()
      ..add(ASN1ObjectIdentifier.fromComponentString('1.2.840.113549.1.1.1'))
      ..add(ASN1Null()));
    publicKeyInfo.add(ASN1BitString(Uint8List.fromList(
        bigIntToBytes(publicKey.modulus!) +
            bigIntToBytes(publicKey.exponent!))));
    asn1.add(publicKeyInfo);

    // Step 5: Sign the CSR structure (without the signature part)
    final signer = Signer('SHA-256/RSA');
    signer.init(true, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    final signature = signer.generateSignature(asn1.encodedBytes);

    // Step 6: Create the signature algorithm identifier
    final sigAlgId = ASN1Sequence();
    sigAlgId.add(ASN1ObjectIdentifier.fromComponentString(
        '1.2.840.113549.1.1.11')); // sha256WithRSAEncryption OID
    sigAlgId.add(ASN1Null());

    // Step 7: Add the signature algorithm identifier and the signature
    final finalSequence = ASN1Sequence()
      ..add(asn1)
      ..add(sigAlgId)
      ..add(
          ASN1BitString(Uint8List.fromList((signature as RSASignature).bytes)));

    // Return the fully encoded CSR with signature
    return finalSequence;
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

  RSAPrivateKey loadPrivateKey(Uint8List keyData) {
    // Step 1: Decode the PEM format if needed
    String pem = String.fromCharCodes(keyData);
    pem = pem.replaceAll('-----BEGIN PRIVATE KEY-----', '');
    pem = pem.replaceAll('-----END PRIVATE KEY-----', '');
    pem = pem.replaceAll('\n', '');
    Uint8List derData = base64.decode(pem);

    // Step 2: Parse the ASN.1 structure
    ASN1Parser asn1Parser = ASN1Parser(derData);
    ASN1Sequence topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    // Step 3: Navigate to the octet string that contains the key data
    ASN1OctetString keyOctetString = topLevelSeq.elements[2] as ASN1OctetString;

    // Step 4: Parse the octet string to access the key components
    ASN1Parser keyParser = ASN1Parser(keyOctetString.octets);
    ASN1Sequence keySeq = keyParser.nextObject() as ASN1Sequence;

    // Extract key components
    BigInt modulus = (keySeq.elements[1] as ASN1Integer).valueAsBigInteger;
    BigInt publicExponent =
        (keySeq.elements[2] as ASN1Integer).valueAsBigInteger;
    BigInt privateExponent =
        (keySeq.elements[3] as ASN1Integer).valueAsBigInteger;
    BigInt p = (keySeq.elements[4] as ASN1Integer).valueAsBigInteger;
    BigInt q = (keySeq.elements[5] as ASN1Integer).valueAsBigInteger;
    BigInt exp1 = (keySeq.elements[6] as ASN1Integer).valueAsBigInteger;
    BigInt exp2 = (keySeq.elements[7] as ASN1Integer).valueAsBigInteger;
    BigInt coeff = (keySeq.elements[8] as ASN1Integer).valueAsBigInteger;

    // Step 5: Create and return the RSAPrivateKey object
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
