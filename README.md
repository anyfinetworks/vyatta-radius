Vyatta CLI for hostapd as standalone RADIUS server
==================================================

# Goals and Objectives

Provide a Vyatta (and EdgeOS) CLI for hostapd operating in standalone RADIUS
server mode (i.e. driver=none). This will allow us to distribute a simple and
easy to use RADIUS server for demonstration purposes.

# Functional Specification

The user will be able to configure a simple RADIUS server with the following
functionality:

1. Demo EAP-PEAP/MSCHAPv2 authentication for use with IEEE 802.11.

2. Demo EAP-SIM authentication for use with IEEE 802.11.

3. Demo splash page functionality (feasibility TBD).

# Configuration Commands

    service
        radius
            identity
                name <txt: SERVER IDENTITY>
                certificate <txt: PEM/DER FILE NAME>
                ca-certificate <txt: PEM/DER FILE NAME>
                private-key <txt: PKCS#12 FILE NAME>

            interface <txt: INTERACE NAME>

            client <txt: RADIUS CLIENT NAME>
                ip-filter <ipnet>
                secret <txt: RADIUS SECRET>

            user
                local
                    peap-mschapv2 <txt: IDENTITY>
                        password <txt: PASSWORD>

                    sim <txt: IDENTITY>
                        triplet <txt: SIM TRIPLET>
                        triplet <txt: SIM TRIPLET>
                        triplet <txt: SIM TRIPLET>

# Operational Commands

    restart
        radius          # Restarts the RADIUS server

