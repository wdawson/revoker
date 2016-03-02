# Introduction
This repository contains a Java 8 implementation of a Certificate Revocation List (CRL) Distribution Point and an Online
Certificate Status Protocol (OCSP) Responder.

# Overview
This app is a Dropwizard app that can respond to CRL requests and OCSP requests for a given CA. You need to provide the app
with access to the index file of the CA, which is effectively the database for the CA, the crl file, and a Java KeyStore
containing the key and certificate chain to sign the OCSP responses with. This is all done within the `conf.yml` file.

[![Build Status](https://travis-ci.org/wdawson/revoker.svg?branch=master)](https://travis-ci.org/wdawson/revoker)

# Running the application

To test the application, run the following commands.

- To package the application, run:

  ```
  mvn package
  ```

- To run the server, run:

  ```
  java -jar target/revoker-0.1.0.jar server conf.yml
  ```

- To use the admin operational menu, navigate a browser to:

  ```
  http://localhost:8081
  ```

- You can use the following openssl command to test that the OCSP works correctly
```
openssl ocsp -CAfile intermediate/certs/ca-chain.cert.pem \
      -url http://127.0.0.1:2560 -resp_text \
      -issuer intermediate/certs/intermediate.cert.pem \
      -cert intermediate/certs/test.example.com.cert.pem
```
