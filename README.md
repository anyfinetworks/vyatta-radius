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

3. Demo authorization and captive portal functionality.

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

            http-portal <txt: NAME>
                document-root <txt: DOCUMENT ROOT>
                ip-address <ipv4>
                tcp-port <u32>

            access <txt: NAME>
                max-bandwidth-up <txt: BPS>
                max-bandwidth-down <txt: BPS>
                max-duration <u32>
                max-volume-down <u32>
                max-volume-up <u32>
                redirect-to <txt: PORTAL NAME>
                block-non-http
                white-list <ipnet>
                vlan-id <u32>

            user
                local
                    peap-mschapv2 <txt: IDENTITY>
                        password <txt: PASSWORD>
                        access <txt: ACCESS NAME>

                    sim <txt: IDENTITY>
                        triplet <txt: SIM TRIPLET>
                        triplet <txt: SIM TRIPLET>
                        triplet <txt: SIM TRIPLET>
                        access <txt: ACCESS NAME>

                    mac <macaddr>
                        access <txt: ACCESS NAME>

                    service
                        ip-address <ipnet>
                            access <txt: ACCESS NAME>

                    nas
                        ip-address <ipnet>
                            access <txt: ACCESS NAME>

                        identifier <txt: IDENTIFIER>
                            access <txt: ACCESS NAME>

# Operational Commands

    restart
        radius          # Restarts the RADIUS server

    show
        radius
            users

    add
        radius
            user <txt: USER NAME>
                service <txt: SERVICE NAME>
                    access <txt: ACCESS NAME>

    delete
        radius
            user <txt: USER NAME>
