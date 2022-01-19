# Secure Data Transmission

A simple **client** which allows you to encrypt and decrypt data using **Java's native Cryptographic APIs**. Named as such because I am not good at naming things.

## Algorithms used

1. `RSA-2048`
2. `AES-256`

## Important information

- This is intended to be used when you wish to secure data while sending it across on the internet. It is air-tight until either the RSA Private or Public Key has been exposed.
- This does NOT handle actual networking operations involved in sending the data to another client over the internet. It is certainly a desirable feature and can be worked on.
- If you wish to transfer keys, refer [here](https://security.stackexchange.com/questions/101560/how-to-securely-send-private-keys) for ways to do so.

## Getting started

- A standard `.jar` file will be set-up in a few days for direct use. Until then, the only solution is to actually build the project.
- This project uses the `Maven` build system. 
- Before trying to build this project, make sure you have Java and Maven installed on your system. This project has been tested to build for OpenJDK 17

## Building the project

```bash
$ git clone https://github.com/suvadityamuk/SecureDataTransmission.git
$ cd SecureDataTransmission
$ mvn package
```

## Future plans

- Improving this README.md with more examples and explanations
- Creating modular interfaces to use this library from Python, Dart and JavaScript
- Increasing number of tests
- Make more robust in terms of reducing encoding-conversions
- Create a system of privileged users who can access the underlying database
- Add functions for direct access to RSA Private and RSA Public Keys to privileged users
- Remove redundant exposure of keys in several different files

## Request for more contributors

- Help me make this a cleaner, better and more dependable piece of software that can be used extensively. Reach out to me via e-mail for any questions. 
