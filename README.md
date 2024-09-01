# flutter_proxy_poc

A new Flutter project.

## Getting Started

This project is a starting point for a Flutter application.

A few resources to get you started if this is your first Flutter project:

- [Lab: Write your first Flutter app](https://docs.flutter.dev/get-started/codelab)
- [Cookbook: Useful Flutter samples](https://docs.flutter.dev/cookbook)

For help getting started with Flutter development, view the
[online documentation](https://docs.flutter.dev/), which offers tutorials,
samples, guidance on mobile development, and a full API reference.

## Setup

```bash
openssl genrsa -out harry-local.key 2048
openssl req -x509 -new -nodes -key harry-local.key -sha256 -days 3650 -out harry-local.pem
openssl genrsa -out harry-proxy.key 2048
openssl req -new -key harry-proxy.key -out harry-proxy.csr
openssl x509 -req -in harry-proxy.csr -CA harry-local.pem -CAkey harry-local.key -CAcreateserial -out harry-proxy.crt -days 365 -sha256
openssl pkcs12 -export -out harry-proxy.p12 -inkey harry-proxy.key -in harry-proxy.crt -certfile harry-local.pem
```
