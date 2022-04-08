import requests
import dataclasses
import time
import jwt
from jwt.algorithms import RSAAlgorithm
import keys


@dataclasses.dataclass
class ShortLivedTokenClient:
    client_id: str
    client_secret: str
    ACCESS_TOKEN_URL: str = "https://api.line.me/v2/oauth/accessToken"

    @classmethod
    def get_headers(cls):
        return {
            "Content-Type": "application/x-www-form-urlencoded"
        }

    def get_payload(self):
        return {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }

    def get_access_token(self):
        headers = self.get_headers()
        payload = self.get_payload()
        response = requests.post(self.ACCESS_TOKEN_URL, data=payload,
                                 headers=headers)
        return response.json()["access_token"]


client = ShortLivedTokenClient(client_id=keys.CHANNEL_ID,
                               client_secret=keys.CHANNEL_SECRET)
print(client.get_access_token())


@dataclasses.dataclass
class ChannelAccessTokenClient:
    channel_id: str
    assertion_signing_key: str
    private_key: dict[str, str]
    token_exp: int
    ACCESS_TOKEN_URL: str = "https://api.line.me/oauth2/v2.1/token"

    def get_jwt_headers(self):
        return {
            "alg": "RS256",
            "typ": "JWT",
            "kid": self.assertion_signing_key
        }

    def get_jwt_payload(self):
        return {
            "iss": self.channel_id,
            "sub": self.channel_id,
            "aud": "https://api.line.me/",
            "exp": int(time.time()) + (60 * 30),
            "token_exp": self.token_exp
        }

    def generate_jwt(self):
        headers = self.get_jwt_headers()
        payload = self.get_jwt_payload()
        signature = RSAAlgorithm.from_jwk(self.private_key)
        return jwt.encode(payload, signature, algorithm="RS256",
                          headers=headers)

    @classmethod
    def get_token_headers(cls):
        return {
            "Content-Type": "application/x-www-form-urlencoded"
        }

    def get_token_payload(self):
        return {
            "grant_type": "client_credentials",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": self.generate_jwt()
        }

    def get_access_token(self):
        headers = self.get_token_headers()
        payload = self.get_token_payload()
        response = requests.post(self.ACCESS_TOKEN_URL, data=payload,
                                 headers=headers)
        return response.json()["access_token"]


cat_client = ChannelAccessTokenClient(
    channel_id=keys.CHANNEL_ID,
    assertion_signing_key=keys.ASSERTION_SIGNING_KEY,
    private_key=keys.PRIVATE_KEY,
    token_exp=60)
print(cat_client.get_access_token())
