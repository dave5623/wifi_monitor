import ConfigParser

from flask import Flask, request, render_template, jsonify
from flask.ext.paginate import Pagination
from flask_sqlalchemy import SQLAlchemy

from wifi_monitor.sniff_thread import Sniff_Thread

# os.remove('wifi_monitor.db')

# airmon-ng check kill && airmon-ng start wlan0

# init Flask app and SQL Alchemy
config = ConfigParser.ConfigParser()
config.read("properties.conf")
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = config.get('main', 'SQLITE_URI')
app.debug = True
db = SQLAlchemy(app)


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


db.create_all()

db.session.commit()

# start sniffing traffic
sniffer = Sniff_Thread()
sniffer.start()


@app.route('/', defaults={'page': 1})
@app.route('/index/page/<int:page>')
@app.route('/index', defaults={'page': 1})
def index(page):
    probe_requests = ProbeRequest.query.order_by(ProbeRequest.timestamp.desc()).all()
    pagination = Pagination(page=page, total=len(probe_requests), search=False, record_name="probe requests")
    print str(pagination)
    return render_template('index.html', probe_requests=probe_requests, pagination=pagination)


def shutdown_server():
    shutdown_func = request.environ.get('werkzeug.server.shutdown')
    if shutdown_func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    shutdown_func()


@app.route('/shutdown')
def shutdown():
    sniffer.stop()
    sniffer.join(10000)
    shutdown_server()
    return 'Server shutting down...'


@app.route('/refresh_probe_requests')
def refresh_probe_requests():
    probe_requests = ProbeRequest.query.order_by(ProbeRequest.timestamp.desc()).all()
    return jsonify(probe_requests=[pr.serialize() for pr in probe_requests])


if __name__ == "__main__":
    try:
        app.run('0.0.0.0', 5000)
    except KeyboardInterrupt:
        print "Caught ctrl-c"
        sniffer.stop()
