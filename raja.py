import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA1
from Crypto.Random import get_random_bytes
from requests import get, Session
import urllib3
import re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_api_key():
    main_page = get("https://www.raja.ir/", verify=False).text
    js_name = re.findall("<script src=\"(main-((?!\.js).)+\.js)\" type=\"module\">", main_page)[-1][0]
    js_file = get(f"https://www.raja.ir/{js_name}", verify=False).text
    api_key = re.search("\"api-key\":\"([^\"]+)\"", js_file).group(1)
    return api_key

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


if __name__ == "__main__":
    password = get_password()
    decrypted = decrypt("RGLB6LZpyZ5qdEzLWyMvXzvJrHjKZcfMxtzy9aAxTP5b+Nzz+BSDUEqAA4ecuSTgOQhc4ipd5sh0M9nR+HfyMQG/DZQGp6FzRKaOiSqEyR8=", password)
    print(decrypted)

    # Stations: https://www.raja.ir/assets/File/station.json
    # FromStation-ToStation-TicketType-MoveType- GoDate -ReturnDate-NumberOfPassengers-CharterCoupe-ExcursionsType-MTCode-Language(L1=Farsi)
    #     161    -    1    -  Family  -   1    -14010901-          -         1        -    false   -       0      -   0  -   L1
    q = encrypt(decrypted, password)
    url = "https://hostservice.raja.ir/Api/ServiceProvider/TrainListEq"
    api_key = get_api_key()
    trains = get(url, params={"q": q}, headers={"api-key": api_key}, verify=False)
    print(json.dumps(trains.json(), indent=4))
