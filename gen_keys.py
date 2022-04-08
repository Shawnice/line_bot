from jwcrypto import jwk
import json

key = jwk.JWK.generate(kty='RSA', alg='RS256', use='sig', size=2048)

private_key = key.export_private()
public_key = key.export_public()


class CryptoKeyGenerator:

    def __init__(self, kty="RSA", alg="RS256", use="sig", size=2048):
        self.key = jwk.JWK.generate(kty=kty, alg=alg, use=use, size=size)

    def get_private_key(self):
        return self.key.export_private()

    def get_public_key(self):
        return self.key.export_public()


ckg = CryptoKeyGenerator()
print(json.dumps(json.loads(ckg.get_private_key()), indent=4))
print()
print(json.dumps(json.loads(ckg.get_public_key()), indent=4))
