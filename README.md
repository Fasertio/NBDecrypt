# NBDecrypt
NetBackup password decryptor

Based on [nbutools](https://github.com/airbus-seclab/nbutools/tree/main)

## Usage

The script can decrypt the AES-256-CRT encrypted password for the DBA and other credentials collected in the Database passing the yekcnedwssap file (encryption key), and vxdbms.conf file (DBA encrypted password). In addition, is possible to decrypt massively credentials in CSV passing it instead of vxdbms.conf file with the (password,passwordkey) header, where password is the encrypted password listed and passwordkey the "TAG".

```
py nbdecrypt.py -h
    _   ______  ____                             __
   / | / / __ )/ __ \___  ____________  ______  / /_
  /  |/ / __  / / / / _ \/ ___/ ___/ / / / __ \/ __/
 / /|  / /_/ / /_/ /  __/ /__/ /  / /_/ / /_/ / /_
/_/ |_/_____/_____/\___/\___/_/   \__, / .___/\__/
                                 /____/_/

usage: nbdecrypt.py [-h] -k YEKCNEDWSSAP -p VXDBMS

Retrieve DBA pwd of NBDB.db

options:
  -h, --help            show this help message and exit
  -k YEKCNEDWSSAP, --yekcnedwssap YEKCNEDWSSAP
                        .yekcnedwssap file path
  -p VXDBMS, --vxdbms VXDBMS
                        vxdbms.conf file path or csv file
```
