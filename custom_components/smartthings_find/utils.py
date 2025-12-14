import logging
import json
import pytz
import base64
import aiohttp
import asyncio
import random
import string
import re
import html
import hashlib
import os
import urllib.parse
from io import BytesIO
from datetime import datetime, timedelta
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import device_registry

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

from .const import (
    DOMAIN, BATTERY_LEVELS, CONF_ACTIVE_MODE_SMARTTAGS, CONF_ACTIVE_MODE_OTHERS,
    CLIENT_ID_AUTH, CLIENT_ID_FIND, SCOPE_AUTH, SCOPE_FIND,
    CONF_ACCESS_TOKEN, CONF_REFRESH_TOKEN, CONF_AUTH_SERVER_URL
)

_LOGGER = logging.getLogger(__name__)

URL_ENTRY_POINT = 'https://account.samsung.com/accounts/ANDROIDSDK/getEntryPoint'
URL_DEVICE_LIST = "https://smartthingsfind.samsung.com/device/getDeviceList.do"
URL_REQUEST_LOC_UPDATE = "https://smartthingsfind.samsung.com/dm/addOperation.do"
URL_SET_LAST_DEVICE = "https://smartthingsfind.samsung.com/device/setLastSelect.do"


def get_random_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def generate_code_verifier():
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('utf-8')


def generate_code_challenge(verifier):
    digest = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('utf-8')


def encrypt_svc_param(svc_param_json, chk_do_num, public_key):
    # 1. SHA-256 hash of chkDoNum
    chk_do_num_hash = hashlib.sha256(str(chk_do_num).encode('utf-8')).digest()
    
    # 2. Random Key 16 bytes
    key = os.urandom(16)
    
    # 3. KDF (PBKDF2) to derive AES key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, 
        salt=key,
        iterations=chk_do_num,
        backend=default_backend()
    )
    # The Wiki specifies using the SHA-256 hash of chkDoNum (base64 encoded) as input for KDF
    derived_key = kdf.derive(base64.b64encode(chk_do_num_hash))

    # 4. Encrypt the Random Key with RSA
    svc_enc_ky = public_key.encrypt(
        key,
        asym_padding.PKCS1v15()
    )
    svc_enc_ky_b64 = base64.b64encode(svc_enc_ky).decode('utf-8')

    # 5. Encrypt Param with AES
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad content
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(svc_param_json.encode('utf-8')) + padder.finalize()
    
    svc_enc_param = encryptor.update(padded_data) + encryptor.finalize()
    svc_enc_param_b64 = base64.b64encode(svc_enc_param).decode('utf-8')
    
    svc_enc_iv = iv.hex()
    
    return svc_enc_param_b64, svc_enc_ky_b64, svc_enc_iv


async def do_login_stage_one(hass: HomeAssistant) -> tuple:
    session = async_get_clientsession(hass)
    
    # 1. Get Entry Point
    async with session.get(URL_ENTRY_POINT) as res:
        if res.status != 200:
            return None, "Failed to get entry point"
        data = await res.json()
        
    sign_in_uri = data['signInURI']
    pki_public_key = data['pkiPublicKey']
    chk_do_num = int(data['chkDoNum'])

    # 2. Generate SVC Param
    state = get_random_string(20)
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    
    # Needed for stage 2
    hass.data.setdefault(DOMAIN, {})['auth_data'] = {
        'state': state,
        'code_verifier': code_verifier
    }

    svc_param = {
        "clientId": CLIENT_ID_AUTH,
        "codeChallenge": code_challenge,
        "codeChallengeMethod": "S256",
        "competitorDeviceYNFlag": "Y",
        "deviceInfo": "Google|com.android.chrome", 
        "deviceModelId": "Pixel 8 Pro",
        "deviceName": "Google Pixel 8 Pro",
        "deviceOSVersion": "35",
        "deviceType": "APP",
        "deviceUniqueId": "ANID", 
        "redirectUri": "ms-app://s-1-15-2-4027708247-2189610-1983755848-2937435718-1578786913-2158692839-1974417358",
        "replaceableClientConnectYN": "N",
        "responseEncryptionType": "1",
        "responseEncryptionYNFlag": "N", # Disable response encryption for simplicity
        "iosYNFlag": "Y", 
        "state": state
    }
    
    svc_param_json = json.dumps(svc_param)
    
    # 3. Encrypt Payload
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        pub_key_bytes = base64.b64decode(pki_public_key)
        try:
            public_key = load_der_public_key(pub_key_bytes, backend=default_backend())
        except:
             # Fallback usually not needed if standard DER
             from cryptography.hazmat.primitives.serialization import load_pem_public_key
             pass
        
        if 'public_key' not in locals():
             raise Exception("Failed to load public key")
        
        svc_enc_param, svc_enc_ky, svc_enc_iv = encrypt_svc_param(svc_param_json, chk_do_num, public_key)

    except Exception as e:
        _LOGGER.error(f"Encryption failed: {e}")
        return None, f"Encryption failed: {e}"

    # 4. Construct URL
    # URL Payload structure: chkDoNum, svcEncParam, svcEncKY, svcKeyIV
    
    # Wait, looking at wiki structure: pattern seems to be key-value pairs or list.
    # "svcParam" is the query parameter name. The value is "URL Payload".
    # The URL Payload contains the 4 items.
    
    payload_dict = {
        "chkDoNum": chk_do_num,
        "svcEncParam": svc_enc_param,
        "svcEncKY": svc_enc_ky,
        "svcKeyIV": svc_enc_iv
    }
    
    # Verify exact keys. Wiki just lists them.
    # `chkDoNum`
    # `svcEncParam`
    # `svcEncKY`
    # `svcKeyIV`
    
    # I'll stick with these keys.
    svc_param_value = json.dumps(payload_dict)
    
    login_url = f"{sign_in_uri}?locale=en&svcParam={urllib.parse.quote(svc_param_value)}&mode=C"

    _LOGGER.info(f"Generated Login URL: {login_url}")
    
    return login_url, None



async def do_login_stage_two(hass: HomeAssistant, redirect_url: str) -> dict:
    session = async_get_clientsession(hass)
    auth_data = hass.data.get(DOMAIN, {}).get('auth_data')
    if not auth_data:
        return None, "Auth data missing. Please restart flow."
    
    state_orig = auth_data['state']
    code_verifier = auth_data['code_verifier']

    # Parse parameters from redirect URL
    import urllib.parse
    parsed = urllib.parse.urlparse(redirect_url)
    params = urllib.parse.parse_qs(parsed.query)
    
    # Parameters needed: code, auth_server_url
    auth_server_url = params.get('auth_server_url', [''])[0]
    code = params.get('code', [''])[0]
    
    # Note: We requested unencrypted response (responseEncryptionYNFlag="N")
    # so we can use the parameters directly without decryption.
    
    # Step 1: Exchange code for user_auth_token
    # POST {auth_server_url}/auth/oauth2/v2/authorize
    # grant_type=authorization_code
    # client_id=CLIENT_ID_AUTH ('yfrtglt53o')
    # code=CODE
    # code_verifier=VERIFIER
    # serviceType=M
    
    async with session.post(
        f"{auth_server_url}/auth/oauth2/v2/authorize",
        data={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID_AUTH,
            "code": code,
            "code_verifier": code_verifier,
            "serviceType": "M"
        },
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    ) as res:
        if res.status != 200:
             return None, f"Token exchange failed: {await res.text()}"
        data = await res.json()
    
    user_auth_token = data.get('userauth_token')
    user_id = data.get('userId')
    
    # Step 2: Get API Token (for Find)
    # First: Authorize to get code for Find
    # GET {auth_server_url}/auth/oauth2/v2/authorize
    # response_type=code
    # client_id=CLIENT_ID_FIND ('27zmg0v1oo')
    # scope=SCOPE_FIND
    # userauth_token=user_auth_token
    # code_challenge_method=S256
    # code_challenge=...
    
    new_verifier = generate_code_verifier()
    new_challenge = generate_code_challenge(new_verifier)
    
    params_auth = {
        "response_type": "code",
        "client_id": CLIENT_ID_FIND,
        "scope": SCOPE_FIND,
        "code_challenge": new_challenge,
        "code_challenge_method": "S256",
        "userauth_token": user_auth_token,
        "serviceType": "M", # Wiki says M
    }
    
    async with session.get(
        f"{auth_server_url}/auth/oauth2/v2/authorize",
        params=params_auth
    ) as res:
        if res.status != 200:
             return None, f"Find authorization failed: {await res.text()}"
        data = await res.json()
        
    find_code = data.get('code')
    
    # Step 3: Exchange Find Code for Access Token
    # POST {auth_server_url}/auth/oauth2/token
    
    async with session.post(
        f"{auth_server_url}/auth/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID_FIND,
            "code": find_code,
            "code_verifier": new_verifier,
        },
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    ) as res:
        if res.status != 200:
             return None, f"Find token exchange failed: {await res.text()}"
        token_data = await res.json()
        
    return token_data, user_id, auth_server_url


# Removed fetch_csrf as it is not needed for OAuth flow with Bearer token



async def refresh_access_token(hass: HomeAssistant, session: aiohttp.ClientSession, entry_id: str):
    """Refreshes the access token using the refresh token."""
    data_store = hass.data[DOMAIN][entry_id]
    refresh_token = data_store.get(CONF_REFRESH_TOKEN)
    auth_server_url = data_store.get(CONF_AUTH_SERVER_URL)
    
    if not refresh_token or not auth_server_url:
        raise ConfigEntryAuthFailed("Refresh token or Auth URL missing")

    try:
        url = f"{auth_server_url}/auth/oauth2/token"
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": CLIENT_ID_FIND
        }
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        
        async with session.post(url, data=payload, headers=headers) as res:
            if res.status != 200:
                _LOGGER.error(f"Token refresh failed: {res.status} - {await res.text()}")
                raise ConfigEntryAuthFailed("Token refresh failed")
            
            data = await res.json()
            
        new_access_token = data.get('access_token')
        new_refresh_token = data.get('refresh_token') # Refresh token rotates? Wiki says: "Note: A refresh token can only be used once, and is replaced with the new one"

        if not new_access_token or not new_refresh_token:
             raise ConfigEntryAuthFailed("Invalid refresh response")

        # Update hass.data
        data_store[CONF_ACCESS_TOKEN] = new_access_token
        data_store[CONF_REFRESH_TOKEN] = new_refresh_token
        
        # Update Config Entry
        entry = hass.config_entries.async_get_entry(entry_id)
        if entry:
            new_data = entry.data.copy()
            new_data[CONF_ACCESS_TOKEN] = new_access_token
            new_data[CONF_REFRESH_TOKEN] = new_refresh_token
            hass.config_entries.async_update_entry(entry, data=new_data)
            _LOGGER.info("Successfully refreshed access token")
            return new_access_token

    except Exception as e:
        _LOGGER.error(f"Error refreshing token: {e}")
        raise ConfigEntryAuthFailed(f"Error refreshing token: {e}")

    except Exception as e:
        _LOGGER.error(f"Error refreshing token: {e}")
        raise ConfigEntryAuthFailed(f"Error refreshing token: {e}")


async def authenticated_request(hass: HomeAssistant, session: aiohttp.ClientSession, entry_id: str, url: str, json_data: dict = None, data: dict = None) -> tuple[int, str]:
    """
    Helper to perform an authenticated request with automatic token refresh.
    
    Returns:
        tuple: (status_code, response_text)
    """
    token = hass.data[DOMAIN][entry_id][CONF_ACCESS_TOKEN]
    headers = {'Authorization': f"Bearer {token}", 'Accept': 'application/json'}
    
    async def _do_req(auth_headers):
        # We prefer JSON if provided, else data (which might be empty dict for get_devices)
        if json_data is not None:
             async with session.post(url, json=json_data, headers=auth_headers) as resp:
                 return resp.status, await resp.text()
        else:
             async with session.post(url, data=data or {}, headers=auth_headers) as resp:
                 return resp.status, await resp.text()

    status, text = await _do_req(headers)
    
    if status in [401, 403]:
        _LOGGER.info(f"Request to {url.split('/')[-1]} returned {status}, refreshing token...")
        try:
            new_token = await refresh_access_token(hass, session, entry_id)
        except Exception as e:
            _LOGGER.error(f"Failed to refresh token: {e}")
            raise ConfigEntryAuthFailed("Token refresh failed")
            
        headers['Authorization'] = f"Bearer {new_token}"
        status, text = await _do_req(headers)
        
        if status in [401, 403]:
             raise ConfigEntryAuthFailed(f"Auth failed after refresh: {status}")
             
    return status, text


def extract_best_location(operations: list, dev_name: str) -> tuple[dict, dict]:
    """
    Extracts the best/newest location from the list of operations.
    Returns (used_op, used_loc).
    """
    used_op = None
    used_loc = {
        "latitude": None,
        "longitude": None,
        "gps_accuracy": None,
        "gps_date": None
    }
    
    for op in operations:
        if op['oprnType'] not in ['LOCATION', 'LASTLOC', 'OFFLINE_LOC']:
            continue
            
        op_data = None
        utc_date = None
        
        # Check standard location
        if 'latitude' in op:
            if 'extra' in op and 'gpsUtcDt' in op['extra']:
                utc_date = parse_stf_date(op['extra']['gpsUtcDt'])
            else:
                 _LOGGER.warning(f"[{dev_name}] No UTC date in operation {op['oprnType']}")
                 continue
            op_data = op

        # Check encrypted/nested location
        elif 'encLocation' in op:
            loc = op['encLocation']
            if loc.get('encrypted'):
                _LOGGER.debug(f"[{dev_name}] Ignoring encrypted location")
                continue
            if 'gpsUtcDt' not in loc:
                 continue
            utc_date = parse_stf_date(loc['gpsUtcDt'])
            op_data = loc
        
        if not op_data or not utc_date:
            continue
            
        # Check if newer
        if used_loc['gps_date'] and used_loc['gps_date'] >= utc_date:
            _LOGGER.debug(f"[{dev_name}] Ignoring older location ({op['oprnType']})")
            continue
            
        # Extract coordinates
        lat = float(op_data['latitude']) if 'latitude' in op_data else None
        lon = float(op_data['longitude']) if 'longitude' in op_data else None
        
        if lat is None or lon is None:
             _LOGGER.warning(f"[{dev_name}] Missing coordinates in {op['oprnType']}")
             # If we have no coords, we preserve 'location_found'=False (implicit by None result)
             # But we might want to track accuracy/date still? 
             # The original code only set location_found=True if lat/lon existed.
             # But it accepted the OP as 'used_op' anyway?
             # "if not locFound: warn ... used_loc['gps_accuracy'] = ... used_op = op"
             # Yes, it updates date/accuracy even if lat/lon missing.
             pass
        
        used_loc['latitude'] = lat
        used_loc['longitude'] = lon
        used_loc['gps_accuracy'] = calc_gps_accuracy(
            op_data.get('horizontalUncertainty'), op_data.get('verticalUncertainty'))
        used_loc['gps_date'] = utc_date
        used_op = op

    if used_op:
        return used_op, used_loc
    return None, None
async def get_devices(hass: HomeAssistant, session: aiohttp.ClientSession, entry_id: str) -> list:
    """
    Sends a request to the SmartThings Find API to retrieve a list of devices associated with the user's account.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        session (aiohttp.ClientSession): The current session.

    Returns:
        list: A list of devices if successful, empty list otherwise.
    """
    auth_header = {'Authorization': f"Bearer {hass.data[DOMAIN][entry_id][CONF_ACCESS_TOKEN]}", 'Accept': 'application/json'}
    
    try:
        status, text = await authenticated_request(hass, session, entry_id, URL_DEVICE_LIST, data={})
        
        if status != 200:
            _LOGGER.error(f"Failed to retrieve devices [{status}]: {text}")
            return []
            
        response_json = json.loads(text)

    except ConfigEntryAuthFailed:
        raise
    except Exception as e:
        _LOGGER.error(f"Error listing devices: {e}")
        return []

    devices_data = response_json["deviceList"]
    devices = []
    for device in devices_data:
        # Double unescaping required. Example:
        # "Benedev&amp;#39;s S22" first becomes "Benedev&#39;s S22" and then "Benedev's S22"
        device['modelName'] = html.unescape(
            html.unescape(device['modelName']))
        identifier = (DOMAIN, device['dvceID'])
        ha_dev = device_registry.async_get(
            hass).async_get_device({identifier})
        if ha_dev and ha_dev.disabled:
             _LOGGER.debug(
                f"Ignoring disabled device: '{device['modelName']}' (disabled by {ha_dev.disabled_by})")
             continue
        ha_dev_info = DeviceInfo(
            identifiers={identifier},
            manufacturer="Samsung",
            name=device['modelName'],
            model=device['modelID'],
            configuration_url="https://smartthingsfind.samsung.com/"
        )
        devices += [{"data": device, "ha_dev_info": ha_dev_info}]
        _LOGGER.debug(f"Adding device: {device['modelName']}")
    return devices


async def get_device_location(hass: HomeAssistant, session: aiohttp.ClientSession, dev_data: dict, entry_id: str) -> dict:
    """
    Sends requests to update the device's location and retrieves the current location data for the specified device.

    Args:
        hass (HomeAssistant): Home Assistant instance.
        session (aiohttp.ClientSession): The current session.
        dev_data (dict): The device information obtained from get_devices.

    Returns:
        dict: The device location data.
    """
    dev_id = dev_data['dvceID']
    dev_name = dev_data['modelName']

    set_last_payload = {
        "dvceId": dev_id,
        "removeDevice": []
    }

    update_payload = {
        "dvceId": dev_id,
        "operation": "CHECK_CONNECTION_WITH_LOCATION",
        "usrId": dev_data['usrId']
    }

    auth_header = {'Authorization': f"Bearer {hass.data[DOMAIN][entry_id][CONF_ACCESS_TOKEN]}", 'Accept': 'application/json'}

    try:
        active = (
            (dev_data['deviceTypeCode'] == 'TAG' and hass.data[DOMAIN][entry_id][CONF_ACTIVE_MODE_SMARTTAGS]) or
            (dev_data['deviceTypeCode'] != 'TAG' and hass.data[DOMAIN]
             [entry_id][CONF_ACTIVE_MODE_OTHERS])
        )

        if active:
            _LOGGER.debug(f"Active mode; requesting location update now for {dev_name}")
            await authenticated_request(hass, session, entry_id, URL_REQUEST_LOC_UPDATE, json_data=update_payload)
        else:
            _LOGGER.debug(f"Passive mode; not requesting location update for {dev_name}")

        status, text = await authenticated_request(hass, session, entry_id, URL_SET_LAST_DEVICE, json_data=set_last_payload)
        
        if status != 200:
             _LOGGER.error(f"[{dev_name}] Failed to fetch location data: {status}")
             _LOGGER.debug(f"[{dev_name}] Full response: {text}")
             if status == 401: # Should have been handled by auth_request reauth logic, so this is double failure
                  raise ConfigEntryAuthFailed("Session invalid")
             return None

        data = json.loads(text)
        
        if data:
            res = {
                "dev_name": dev_name,
                "dev_id": dev_id,
                "update_success": True, # We assume True if API returns 200, even if location not found
                "location_found": False,
                "used_op": None,
                "used_loc": None,
                "ops": []
            }
            
            if 'operation' in data and len(data['operation']) > 0:
                res['ops'] = data['operation']
                
                # Use helper to extract best location
                used_op, used_loc = extract_best_location(data['operation'], dev_name)
                
                if used_op:
                    res['used_op'] = used_op
                    res['used_loc'] = used_loc
                    res['location_found'] = True # Our helper returns None if no location found
                else:
                    _LOGGER.warning(f"[{dev_name}] No usable location operation found")
                    
                _LOGGER.debug(f"    --> {dev_name} used operation: {'NONE' if not used_op else used_op['oprnType']}")
            else:
                 _LOGGER.warning(f"[{dev_name}] No operations found in response")
                 res['update_success'] = False
                 
            return res

    except ConfigEntryAuthFailed as e:
        raise
    except Exception as e:
        _LOGGER.error(
            f"[{dev_name}] Exception occurred while fetching location data for tag '{dev_name}': {e}", exc_info=True)

    return None


def calc_gps_accuracy(hu: float, vu: float) -> float:
    """
    Calculate the GPS accuracy using the Pythagorean theorem.
    Returns the combined GPS accuracy based on the horizontal
    and vertical uncertainties provided by the API

    Args:
        hu (float): Horizontal uncertainty.
        vu (float): Vertical uncertainty.

    Returns:
        float: Calculated GPS accuracy.
    """
    try:
        return round((float(hu)**2 + float(vu)**2) ** 0.5, 1)
    except ValueError:
        return None


def get_sub_location(ops: list, subDeviceName: str) -> tuple:
    """
    Extracts sub-location data for devices that contain multiple
    sub-locations (e.g., left and right earbuds).

    Args:
        ops (list): List of operations from the API.
        subDeviceName (str): Name of the sub-device.

    Returns:
        tuple: The operation and sub-location data.
    """
    if not ops or not subDeviceName or len(ops) < 1:
        return {}, {}
    for op in ops:
        if subDeviceName in op.get('encLocation', {}):
            loc = op['encLocation'][subDeviceName]
            sub_loc = {
                "latitude": float(loc['latitude']),
                "longitude": float(loc['longitude']),
                "gps_accuracy": calc_gps_accuracy(loc.get('horizontalUncertainty'), loc.get('verticalUncertainty')),
                "gps_date": parse_stf_date(loc['gpsUtcDt'])
            }
            return op, sub_loc
    return {}, {}


def parse_stf_date(datestr: str) -> datetime:
    """
    Parses a date string in the format "%Y%m%d%H%M%S" to a datetime object.
    This is the format, the SmartThings Find API uses.

    Args:
        datestr (str): The date string in the format "%Y%m%d%H%M%S".

    Returns:
        datetime: A datetime object representing the input date string.
    """
    return datetime.strptime(datestr, "%Y%m%d%H%M%S").replace(tzinfo=pytz.UTC)


def get_battery_level(dev_name: str, ops: list) -> int:
    """
    Try to extract the device battery level from the received operation

    Args:
        dev_name (str): The name of the device.
        ops (list): List of operations from the API.

    Returns:
        int: The battery level if found, None otherwise.
    """
    for op in ops:
        if op['oprnType'] == 'CHECK_CONNECTION' and 'battery' in op:
            batt_raw = op['battery']
            batt = BATTERY_LEVELS.get(batt_raw, None)
            if batt is None:
                try:
                    batt = int(batt_raw)
                except ValueError:
                    _LOGGER.warn(
                        f"[{dev_name}]: Received invalid battery level: {batt_raw}")
            return batt
    return None



