# Strengthening of Tor Against Traffic Correlation with K-Anonymity Input Circuits

# Guide

## Repository Organization

This repository is split into six main folders:

* <strong> Analytics </strong>: Holds our feature extraction and classification scripts.
* <strong> AutomatedClient </strong>: Holds the code for the automated client.
* <strong> Environment </strong>: Holds the JAR executable of the two type of clients, the TIR and the HttpServer for setting up our VMs & reproducing our lab environment.
* <strong> HttpServer </strong>: Holds the code of the HTTP file server.
* <strong> InteractiveClient </strong>: Holds the code for the interactive client.
* <strong> TIR </strong>: Holds the code for the TIR solution.

## Requirements

To run our solution, its required: Java v11.0 or higher, Tor v0.4.4.6 or higher, Stunnel v5.57 or higher.

## Solution Setup

Our laboratory setup assumes the existence of 1 local machine running a 64 bits Linux Ubuntu 20.04, vCore 4 (VPS, w/ dedicated 4-Cores) Processor, 8 GB of RAM, NVMe SSD 160 GB Storage and a minimum of 2 VMs running a 64 bits Linux Ubuntu 20.04, vCore 1 (VPS, w/ dedicated 1-Cores) Processor, 2 GB of RAM, NVMe SSD 40 GB Storage, running in separate physical machines. While this configuration may be adjusted to better suit your needs, this setup guide follows the details of the figure below. 

### Lab network setup
![](https://github.com/joaoteixeira96/Thesis/Environment/EnvironmentSetup.png)

1. Configure Stunnel

Before spinning up the VMs, we need to configure Stunnel service, for each machine with TIR installed, copy the /Environment/stunnel.conf file and paste into the default Stunnel configuration file path "/etc/stunnel/". Some parameters in the file must be changed according to the personal setup: <strong> cert </strong> is the certification file path which is located in /TIR/keystore/tir.cert, <strong> key </strong> is the private key file path which is located in /TIR/keystore/tir.pem, <strong> accept </strong> IP:port which Stunnel accepts connections, <strong> connect </strong> IP:port where the TIR wishes to connect to (another TIR).

2. Configure and Spin up Java JARs

The second step of this guide involves configure the VMs, minimum of 2 acting as the Client/TIR and one machine for the server machine acting like some free Internet service. One Client/TIR can run on the local physical machine and the others on different physical machines.

* <strong> HttpServer </strong>: On a VM we install and run the executable JAR HttpServer located in /Environment/HttpServer by command "java -jar HttpServer.jar". Note that there is a folder named Files where locates the files that the clients wishes to request.
* <strong> TIR </strong>: On a VM we install and run the executable JAR TIR located in /Environment/TIR by command "java -jar TIR.jar". Note that there are 2 folders name keystore, which holds the respective files (certificate, keys) for secure connections, and configuration containing 2 files: <strong> TIR_network </strong>: List of setup TIRs to connect and <strong> config.properties </strong>: All the TIR configurations: local_host - IP of the local host, local_port_unsecure - Port for TCP and UDP requests, local_port_secure - Port for TLS and DTLS requests, remote_host - IP of HttpServer, remote_port = Port of HttpServer, stunnel_port = Accept port parameter of Stunnel service, bypass_timer = Selection of random TIR timer in milliseconds, tor_buffer_size = packet chunk sizes for Tor, number_of_tirmmrt = number of TIR to select, and the rest of the configrations are for test purposes.
* <strong> InteractiveClient </strong>: On a VM we install and run the executable JAR InteractiveClient located in /Environment/InteractiveClient by command "java -jar InteractiveClient.jar". Note that there are 2 folders name keystore, which holds the respective files (certificate, keys) for secure connections, and configuration containing 1 files: <strong> config.properties </strong>: All the client configurations: remote_host = IP of the respective TIR, remote_port_unsecure = Port of the respective TIR for TCP and UDP requests, remote_port_secure = Port of the respective TIR for TLS and DTLS requests.

3. Client/TIR usage

Once we setup and run TIR and it's client on one machine, make sure Tor (with the default settings) and Stunnel service are running, we start requesting files to the HttpServer using interactive client shell, using requests like: (e.g, "/Files/small tcp"), this indicates we want a file called small using tcp protocol. Usage: File_Path protocol(tcp,udp,tls,dtls).

