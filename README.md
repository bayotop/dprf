# Distributed Password Recovery Framework

The whole system consists of 3 logically separated parts – client-server modules handling communication and synchronization, document parsers, and a brute-force engine for password recovery. The basic idea is that the server part acts as the main entry point for the user and handles all additional work. It utilizes a document parser to gather information necessary for password verification and distributes work among all active clients.

The input for the system is a password protected Office, PDF or ODF document. As the password verification process can be very different among these formats, a detailed list of currently supported algorithms follows:

* MS Office (Open Office XML - ECMA-376) – Standard Encryption
* Portable Document Format – version 1.3 to 1.7 using standard security handlers from version 1 to 5 and revision 2 to 6
* Open Document Format – version 1.2 using AES-256

Note that the current version must be run with Python 2.7 in order to function properly.

## Document Parsers

The document parsers are stand-alone Python scripts that take document files as input and return all data necessary for the verification process. Note that the scripts used to extract information from PDF and MS Office files were not created as part of this thesis, but were taken from the public [John the Ripper GitHub repository](https://github.com/magnumripper/JohnTheRipper). Small modifications were made to these scripts, to better fit into the developed system. All changes are included as comments in the respective files.

## Server

The server provides a simple command line interface and can be started using the following command:

```
$ server.py [-h] [-pr PASSWORDRANGE ] [-ps PAYLOADSIZE ] document_type filename tcp_ip tcp_port
```
* **-h** – Shows a descriptive help message.
* **-pr** – Sets the password’s maximum length (default: 8). Note that all passwords up to the specified length will be checked.
* **-ps** – Number of passwords sent to each client on every connection (default: 20,000).
* **document_type** – Number identifying the given document’s type.
 * 1 – Microsoft Office
 * 2 – Open Document Format 
 * 3 – Portable Document Format
* **filename** – Path to the document file whose password should be recovered.
* **tcp_ip** – IP address.
* **tcp_port** – Port number.

## Client

The client can be run using the following command:
```
$ client.py [-h] tcp_ip tcp_port
```
The tcp_ip and tcp_port are the connection parameters used to communicate with the server. The optional –h argument will show a descriptive help message.

## Brute-force engine

The brute-force engine can be used either as a stand-alone Python script providing a simple command line interface, or as a Python module. When run separately, it can be started using the following command:

```
$ brute_force.py [-h] [-pr PASSWORDRANGE ] document_type filename
```

### Compilation:
```
gcc -o src/ms-offcrypto-impl/msoffcrypto src/ms-offcrypto-impl/msoffcrypto_password_verifier.c -lssl -lcrypto
gcc -o src/odt-impl/odt src/odt-impl/odt_password_verifier.c -lssl -lcrypto
gcc -o src/pdf-impl/pdf src/pdf-impl/pdf_password_verifier.c -lssl -lcrypto
```

For more detailed information see https://is.muni.cz/th/396204/fi_m/thesis.pdf (chapter 6).
