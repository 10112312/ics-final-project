import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKC
from Crypto import Random


class HandleRSA():
    def create_rsa_key(self):
        # pseudo random number generator
        random_gen = Random.new().read
        # Generate key pair instance object: 1024 is the length of the key
        rsa = RSA.generate(1024, random_gen)

        # Server
        private_pem = rsa.exportKey()
        with open("server_private.pem", "wb") as f:
            f.write(private_pem)

        public_pem = rsa.publickey().exportKey()
        with open("server_public.pem", "wb") as f:
            f.write(public_pem)

        # Client
        private_pem = rsa.exportKey()
        with open("client_private.pem", "wb") as f:
            f.write(private_pem)

        public_pem = rsa.publickey().exportKey()
        with open("client_public.pem", "wb") as f:
            f.write(public_pem)

    # Server use the public key of Client to encrypt
    def encrypt(self, plaintext):

        # public key
        rsa_key = RSA.import_key(open("client_public.pem").read() )

        # encrypt
        cipher_rsa = Cipher_PKC.new(rsa_key)
        en_data = cipher_rsa.encrypt(plaintext.encode("utf-8")) 

        # base64 encode
        base64_text = base64.b64encode(en_data)

        return base64_text.decode() # string

    # Client use the private key to decrypt
    def decrypt(self, en_data):

        # base64 decode
        base64_data = base64.b64decode(en_data.encode("utf-8"))

        # get private key
        private_key = RSA.import_key(open("client_private.pem").read())

        # decrypt
        cipher_rsa = Cipher_PKC.new(private_key)
        data = cipher_rsa.decrypt(base64_data,None)

        return data.decode()


if __name__ == '__main__':

    mrsa = HandleRSA()
    mrsa.create_rsa_key()
    e = mrsa.encrypt('hello vicky')
    d = mrsa.decrypt(e)
    print(e)
    print(d)
   