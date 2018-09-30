# Python module to interface with Shenzhen Xenon ESP8266MOD WiFi smart devices
# E.g. https://wikidevi.com/wiki/Xenon_SM-PW701U
#   SKYROKU SM-PW701U Wi-Fi Plug Smart Plug
#   Wuudi SM-S0301-US - WIFI Smart Power Socket Multi Plug with 4 AC Outlets and 4 USB Charging Works with Alexa
#
# This would not exist without the protocol reverse engineering from
# https://github.com/codetheweb/tuyapi by codetheweb and blackrozes
#
# Tested with Python 2.7 and Python 3.6.1 only


import base64
from hashlib import md5
import json
import logging
import socket
import sys
import time
import colorsys
import struct

try:
    #raise ImportError
    import Crypto
    from Crypto.Cipher import AES  # PyCrypto
except ImportError:
    Crypto = AES = None
    import pyaes  # https://github.com/ricmoo/pyaes


log = logging.getLogger(__name__)
logging.basicConfig()  # TODO include function name/line numbers in log
#log.setLevel(level=logging.DEBUG)  # Debug hack!

log.info('Python %s on %s', sys.version, sys.platform)
if Crypto is None:
    log.info('Using pyaes version %r', pyaes.VERSION)
    log.info('Using pyaes from %r', pyaes.__file__)
else:
    log.info('Using PyCrypto %r', Crypto.version_info)
    log.info('Using PyCrypto from %r', Crypto.__file__)

SET = 'set'
RESOLVE_PORT=6666

PROTOCOL_VERSION_BYTES = b'3.1'

IS_PY2 = sys.version_info[0] == 2

class AESCipher(object):
    def __init__(self, key):
        #self.bs = 32  # 32 work fines for ON, does not work for OFF. Padding different compared to js version https://github.com/codetheweb/tuyapi/
        self.bs = 16
        self.key = key
    def encrypt(self, raw):
        if Crypto:
            raw = self._pad(raw)
            cipher = AES.new(self.key, mode=AES.MODE_ECB)
            crypted_text = cipher.encrypt(raw)
        else:
            _ = self._pad(raw)
            cipher = pyaes.blockfeeder.Encrypter(pyaes.AESModeOfOperationECB(self.key))  # no IV, auto pads to 16
            crypted_text = cipher.feed(raw)
            crypted_text += cipher.feed()  # flush final block
        #print('crypted_text %r' % crypted_text)
        #print('crypted_text (%d) %r' % (len(crypted_text), crypted_text))
        crypted_text_b64 = base64.b64encode(crypted_text)
        #print('crypted_text_b64 (%d) %r' % (len(crypted_text_b64), crypted_text_b64))
        return crypted_text_b64
    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        #print('enc (%d) %r' % (len(enc), enc))
        #enc = self._unpad(enc)
        #enc = self._pad(enc)
        #print('upadenc (%d) %r' % (len(enc), enc))
        if Crypto:
            cipher = AES.new(self.key, AES.MODE_ECB)
            raw = cipher.decrypt(enc)
            #print('raw (%d) %r' % (len(raw), raw))
            return self._unpad(raw).decode('utf-8')
            #return self._unpad(cipher.decrypt(enc)).decode('utf-8')
        else:
            cipher = pyaes.blockfeeder.Decrypter(pyaes.AESModeOfOperationECB(self.key))  # no IV, auto pads to 16
            plain_text = cipher.feed(enc)
            plain_text += cipher.feed()  # flush final block
            return plain_text
    def _pad(self, s):
        padnum = self.bs - len(s) % self.bs
        return s + padnum * chr(padnum).encode()
    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


def bin2hex(x, pretty=False):
    if pretty:
        space = ' '
    else:
        space = ''
    if IS_PY2:
        result = ''.join('%02X%s' % (ord(y), space) for y in x)
    else:
        result = ''.join('%02X%s' % (y, space) for y in x)
    return result


def hex2bin(x):
    if IS_PY2:
        return x.decode('hex')
    else:
        return bytes.fromhex(x)

# This is intended to match requests.json payload at https://github.com/codetheweb/tuyapi
payload_dict = {
  "device": {
    "status": {
      "hexByte": "0a",
      "command": {"gwId": "", "devId": ""}
    },
    "set": {
      "hexByte": "07",
      "command": {"devId": "", "uid": "", "t": ""}
    },
    "prefix": "000055aa00000000000000",    # Next byte is command byte ("hexByte") some zero padding, then length of remaining payload, i.e. command + suffix (unclear if multiple bytes used for length, zero padding implies could be more than one byte)
    "suffix": "000000000000aa55"
  }
}

class TuyaDevice(object):
    def __init__(self, dev_id, local_key, address=None, dev_type=None, connection_timeout=10):
        """
        Represents a Tuya device.
        
        Args:
            dev_id (str): The device id.
            address (str): The network address.
            local_key (str, optional): The encryption key. Defaults to None.
            dev_type (str, optional): The device type.
                It will be used as key for lookups in payload_dict.
                Defaults to None.
            
        Attributes:
            port (int): The port to connect to.
        """
        self.id = dev_id
        self.address = address
        self.local_key = local_key
        self.local_key = local_key.encode('latin1')
        self.dev_type = dev_type
        self.connection_timeout = connection_timeout
        self.version = PROTOCOL_VERSION_BYTES
        self.port = 6668  # default - do not expect caller to pass in
        self.uid = ''

    def __repr__(self):
        return '%r' % ((self.id, self.address),)  # FIXME can do better than this


    def _resolveId(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(10)
        try:
            log.info('Binding to local port %d', RESOLVE_PORT)
            sock.bind(('<broadcast>', RESOLVE_PORT))
        except:
            pass
        try:
            data, addr = sock.recvfrom(2048)
            log.debug('Received=%s:%s', data, addr)
            (error,result) = self._extract_payload(data)
        except socket.timeout:
            log.error('No data received during resolveId call')
            error = True

        if(error == False):
            log.debug('Resolve string=%s', result)
            thisId = result['gwId']
            if (self.id == thisId):
                # Add IP
                self.address = result['ip']
                # Change product key if neccessary
                self.productKey = result['productKey'].encode('latin1')

                # Change protocol version if necessary
                self.version = result['version']
        sock.close()
        return error


    def _send_receive(self, payload):
        """
        Send single buffer `payload` and receive a single buffer.
        
        Args:
            payload(bytes): Data to send.
        """
        if (self.address == None):
            self._resolveId()
        data = None
        for i in range(4):       
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(self.connection_timeout)
            try:
                log.debug('Attempt(%d);Connecting to = %s:%i', i, self.address, self.port)
                s.connect((self.address, self.port))
                log.debug('Sending :  %s', payload)
                s.send(payload)
                data = s.recv(1024)
            except (ConnectionResetError, ConnectionRefusedError) as e:
                log.error('Send/receive exeption :  %s', e)
                data = None
            finally:
                s.close() 
            if (data != None):
                break
        return data 
        
    def generate_payload(self, command, data=None):
        """
        Generate the payload to send.

        Args:
            command(str): The type of command.
                This is one of the entries from payload_dict
            data(dict, optional): The data to be send.
                This is what will be passed via the 'dps' entry
        """
        json_data = payload_dict[self.dev_type][command]['command']

        if 'gwId' in json_data:
            json_data['gwId'] = self.id
        if 'devId' in json_data:
            json_data['devId'] = self.id
        if 'uid' in json_data:
            json_data['uid'] = self.uid  
        if 't' in json_data:
            json_data['t'] = str(int(time.time()))

        if data is not None:
            json_data['dps'] = data

        # Create byte buffer from hex data
        json_payload = json.dumps(json_data)
        #print(json_payload)
        json_payload = json_payload.replace(' ', '')  # if spaces are not removed device does not respond!
        json_payload = json_payload.encode('utf-8')
        log.debug('json_payload=%r', json_payload)

        if command == SET:
            # need to encrypt
            #print('json_payload %r' % json_payload)
            self.cipher = AESCipher(self.local_key)  # expect to connect and then disconnect to set new
            json_payload = self.cipher.encrypt(json_payload)
            #print('crypted json_payload %r' % json_payload)
            preMd5String = b'data=' + json_payload + b'||lpv=' + PROTOCOL_VERSION_BYTES + b'||' + self.local_key
            #print('preMd5String %r' % preMd5String)
            m = md5()
            m.update(preMd5String)
            #print(repr(m.digest()))
            hexdigest = m.hexdigest()
            #print(hexdigest)
            #print(hexdigest[8:][:16])
            json_payload = PROTOCOL_VERSION_BYTES + hexdigest[8:][:16].encode('latin1') + json_payload
            #print('data_to_send')
            #print(json_payload)
            #print('crypted json_payload (%d) %r' % (len(json_payload), json_payload))
            #print('json_payload  %r' % repr(json_payload))
            #print('json_payload len %r' % len(json_payload))
            #print(bin2hex(json_payload))
            self.cipher = None  # expect to connect and then disconnect to set new


        postfix_payload = hex2bin(bin2hex(json_payload) + payload_dict[self.dev_type]['suffix'])
        #print('postfix_payload %r' % postfix_payload)
        #print('postfix_payload %r' % len(postfix_payload))
        #print('postfix_payload %x' % len(postfix_payload))
        #print('postfix_payload %r' % hex(len(postfix_payload)))
        assert len(postfix_payload) <= 0xff
        postfix_payload_hex_len = '%x' % len(postfix_payload)  # TODO this assumes a single byte 0-255 (0x00-0xff)
        buffer = hex2bin( payload_dict[self.dev_type]['prefix'] + 
                          payload_dict[self.dev_type][command]['hexByte'] + 
                          '000000' +
                          postfix_payload_hex_len ) + postfix_payload
        #print('command', command)
        #print('prefix')
        #print(payload_dict[self.dev_type][command]['prefix'])
        #print(repr(buffer))
        #print(bin2hex(buffer, pretty=True))
        #print(bin2hex(buffer, pretty=False))
        #print('full buffer(%d) %r' % (len(buffer), buffer))
        return buffer
    
    def _extract_payload(self,data):
        """ Return the dps status in json format in a tuple (bool,json)
            if(bool): an error occur and the json is not relevant
            else: no error detected and the status is in json format
        
        Args:
            data: The data received by _send_receive function       
        """ 
        # Check for length
        if (len(data) < 16):
            log.debug('Packet too small. Length: %d', len(data))
            return True

        if (data.startswith(b'\x00\x00U\xaa') == False):
            raise ValueError('Magic prefix mismatch : %s',data)

        if (data.endswith(b'\x00\x00\xaaU') == False):
            raise ValueError('Magic suffix mismatch : %s',data)

        payloadSize = struct.unpack_from('>I',data,12)[0]
        log.debug('payloadSize = %i', payloadSize)
        
        # Check for payload
        if (len(data) - 8 < payloadSize):
            log.debug('Packet missing payload. %i;%i', len(data), payloadSize)
            return True
        
        # extract payload without prefix, suffix, CRC
        payload = data[20:20+payloadSize-12]
        log.warning('payload = %s', payload)
        payload = json.loads(payload.decode())
        return (False,payload) 
                                                              

    
    def status(self):
        log.debug('status() entry')
        payload = self.generate_payload('status')
        data = self._send_receive(payload)
        log.debug('status received data=%r', data)

        (error,result) = self._extract_payload(data)
        if(error):
            raise TypeError('Unexpected status() payload=%r', data)
        else:
            return result
    
    def set_status(self, on, switch=1):
        """
        Set status of the device to 'on' or 'off'.
        
        Args:
            on(bool):  True for 'on', False for 'off'.
            switch(int): The switch to set
        """

        if isinstance(switch, int):
            switch = str(switch)  # index and payload is a string
        payload = self.generate_payload(SET, {switch:on})

        data = self._send_receive(payload)
        log.debug('set_status received data=%r', data)

        return data
        #(error,result) = self.extract_payload(data)
        #if(not error):
        #   return result
        #else:
        #   return ""
        #else:
        #   return self.status()

    def turn_on(self, switch=1):
        """Turn the device on"""
        return self.set_status(True, switch)

    def turn_off(self, switch=1):
        """Turn the device off"""
        return self.set_status(False, switch)

    def resolveId(self):
        """Resolve device IP"""
        return self._resolveId()

    def set_timer(self, num_secs):
        """
        Set a timer.
        
        Args:
            num_secs(int): Number of seconds
        """
        # FIXME / TODO support schemas? Accept timer id number as parameter?

        # Dumb heuristic; Query status, pick last device id as that is probably the timer
        status = self.status()
        devices = status['dps']
        devices_numbers = list(devices.keys())
        devices_numbers.sort()
        dps_id = devices_numbers[-1]

        payload = self.generate_payload(SET, {dps_id:num_secs})

        data = self._send_receive(payload)
        log.debug('set_timer received data=%r', data)
        return data

class OutletDevice(TuyaDevice):
    def __init__(self, dev_id, local_key, address=None):
        dev_type = 'device'
        super(OutletDevice, self).__init__(dev_id, local_key, address, dev_type)