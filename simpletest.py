#!/usr/bin/env python3

import logging
import time
import pytuya

dev_id = '05200058dc4f22850214'
local_key = 'e04346aada4d6c51'
addr = None
d = pytuya.TuyaDevice(dev_id, local_key, '192.168.1.220', 'device')
d.resolveId()
#d.status()
#d.status()
d.turn_on()
time.sleep(3)
d.status()
#time.sleep(2)
d.turn_off()
#time.sleep(2)
#d.status()
print(d)
