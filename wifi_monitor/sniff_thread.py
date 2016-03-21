import binascii
import datetime
import pcapy
import threading
import warnings

import impacket
import requests
from expiringdict import ExpiringDict
from impacket import ImpactDecoder
import shared
import models

"""
http://stackoverflow.com/questions/323972/is-there-any-way-to-kill-a-thread-in-python
"""


class Sniff_Thread(threading.Thread):
    def __init__(self, cache_size, cache_timeout_seconds):
        super(Sniff_Thread, self).__init__()
        self._stop = threading.Event()
        self.cache_size = cache_size
        self.cache_timeout_seconds = cache_timeout_seconds

    def stop(self):
        self._stop.set()

    def stopped(self):
        return self._stop.isSet()

    def run(self):

        cache = ExpiringDict(max_len=self.cache_size, max_age_seconds=self.cache_timeout_seconds)

        cap = pcapy.open_live("wlan0mon", 65536, 1, 0)

        while (not self.stopped()):
            try:
                (header, packet) = cap.next()
                radioDecoder = ImpactDecoder.RadioTapDecoder()
                radioData = radioDecoder.decode(packet)
                dot11 = radioData.child()
                if dot11.get_type() == impacket.dot11.Dot11Types.DOT11_TYPE_MANAGEMENT and dot11.get_subtype() == impacket.dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_PROBE_REQUEST:
                    base = dot11.child().child()
                    bssid_base = dot11.child()
                    ssid = base.get_ssid()
                    bssid = self.getBssid(bssid_base.get_bssid())
                    source_address = self.getBssid(bssid_base.get_source_address())
                    destination_address = self.getBssid(bssid_base.get_destination_address())
                    src_vendor = self.resolve_oui(str(source_address).replace(':', '-'))
                    bssid_vendor = self.resolve_oui(str(bssid).replace(':', '-'))

                    header = radioData.get_header_as_string()
                    hex_header = binascii.hexlify(header)
                    # raw SSI signal field from radio header converted to decimal
                    rssi_dbm = int("0x" + hex_header[-4:-2], 16)
                    # converting SSI signal field to appear the same way as wireshark
                    rssi_dbm = -(256 - rssi_dbm)

                    probe_request = models.ProbeRequest(str(base.get_ssid()), str(bssid), bssid_vendor, source_address,
                                                        src_vendor, str(rssi_dbm), datetime.datetime.now(), '', False)
                    # print probe_request
                    key = (probe_request.src, probe_request.ssid)

                    # if we've seen a probe request from a device and an SSID within the past CACHE_TIMEOUT_SECONDS
                    # then put it in the cache and don't insert it into the database
                    if (key not in cache):
                        if (probe_request.src not in shared.whitelisted_devices):
                            shared.db.session.add(probe_request)
                            shared.db.session.commit()
                            shared.db.session.flush()
                            print "[+] New Probe Request detected: " + str(probe_request)
                            cache[key] = None
                        else:
                            print str(probe_request.src) + " is whitelisted not added"
                    else:
                        # reset the timeout for this device and SSID tuple
                        cache[key] = None
                        print str(key) + " is in the cache and will not be added"

            except Exception as e:
                print "[ERROR] Could not parse packet! " + str(e)
                pass

    def resolve_oui(self, mac):
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            try:
                response = requests.get('https://www.macvendorlookup.com/api/v2/%s' % mac.upper(), verify=False)
                if response.status_code == 200:
                    data = response.json()
                    return data[0]['company']
                else:
                    return 'Unknown'
            except:
                return 'Unknown'

    def getBssid(self, arr):
        # Get Binary array to MAC addr format
        out = []
        s = binascii.hexlify(arr)
        t = iter(s)
        st = ':'.join(a + b for a, b in zip(t, t))
        return st
