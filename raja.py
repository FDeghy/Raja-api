import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA1
from Crypto.Random import get_random_bytes
from requests import get

def get_password():
    json_data = get("https://www.raja.ir/assets/File/xrs.json", verify=False).text.encode("utf-8")
    master_key = json.loads(json_data)["Key"]
    return master_key

def decrypt(q: str, password=get_password()):
    q = base64.b64decode(q)
    rand1 = q[:16]
    iv = q[16:32]
    cipher = q[32:]
    key = PBKDF2(password, rand1, 32, count=100, hmac_hash_module=SHA1)
    d = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher), AES.block_size).decode()
    return d

def encrypt(q: str, password=get_password()):
    rand1 = get_random_bytes(16)
    iv = get_random_bytes(16)
    key = PBKDF2(password, rand1, 32, count=100, hmac_hash_module=SHA1)
    cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(q.encode(), AES.block_size))
    e = base64.b64encode(rand1 + iv + cipher).decode()
    return e


password = get_password()
decrypted = decrypt("WGFpvi9BCKBrhakYl+2Q0rUNjxPGfloSL+oO1DDCTqmT7txE7PJvBmITVseUiLYlbjf93pmDs+4R6qz+Shynfh6J71iDhqihW9vaCBwxocE=", password)
print(decrypted)

# Stations: https://www.raja.ir/assets/File/station.json
# FromStation-ToStation-TicketType-MoveType- GoDate -ReturnDate-NumberOfPassengers-CharterCoupe-ExcursionsType-MTCode-Language(L1=Farsi)
#     161    -    1    -  Family  -   1    -14010901-          -         1        -    false   -       0      -   0  -   L1
q = encrypt("161-1-Family-1-14010901--1-false-0-0-L1", password)
url = "https://hostservice.raja.ir/Api/ServiceProvider/TrainListEq"
trains = get(url, params={"q": q}, verify=False).json()

print(json.dumps(trains, indent=4))