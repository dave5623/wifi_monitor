from shared import db

class ProbeRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ssid = db.Column(db.String(32))
    bssid = db.Column(db.String(17))
    bssid_vendor = db.Column(db.String(255))
    src = db.Column(db.String(17))
    src_vendor = db.Column(db.String(255))
    ssi_signal = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime)
    alias = db.Column(db.String(255))
    whitelist = db.Column(db.Boolean)

    def __init__(self, ssid, bssid, bssid_vendor, src, src_vendor, ssi_signal, timestamp, alias, whitelist):
        self.ssid = ssid
        self.bssid = bssid
        self.bssid_vendor = bssid_vendor
        self.src = src
        self.src_vendor = src_vendor
        self.ssi_signal = ssi_signal
        self.timestamp = timestamp
        self.alias = alias
        self.whitelist = whitelist

    def __repr__(self):
        return '<ProbeRequest> ID: %s SSID: %s BSSID: %s (Vendor: %s) Device: %s (Vendor: %s) SSI Signal: %s Timestamp: %s' % (
            str(self.id), self.ssid, self.bssid, self.bssid_vendor, self.src, self.src_vendor, str(self.ssi_signal),
            self.timestamp.strftime('%Y-%m-%d %H:%M'))

    def serialize(self):
        return {
            'id': self.id,
            'ssid': self.ssid,
            'bssid': self.bssid,
            'bssid_vendor': self.bssid_vendor,
            'src': self.src,
            'src_vendor': self.src_vendor,
            'ssi_signal': self.ssi_signal,
            'timestamp': self.timestamp,
            'alias': self.alias,
            'whitelist': self.whitelist
        }