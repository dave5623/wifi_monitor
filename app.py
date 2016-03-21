import ConfigParser
import ast
import sys

from flask import Flask, request, render_template, jsonify, redirect, flash
from flask.ext.babel import Babel, format_datetime
from flask.ext.paginate import Pagination
from flask.ext.wtf import CsrfProtect
from sqlalchemy import func, desc

import models
import shared
import wifi_monitor.sniff_thread
from edit_probe_request_form import EditProbeRequestForm

sys.dont_write_bytecode = True
# dmesg -wH
# airmon-ng check kill && airmon-ng start wlan0

DEBUG = True
print "[+] STARTING SNIFFER THREAD"

# init Flask app and SQL Alchemy
config = ConfigParser.ConfigParser()
config.read("properties.conf")
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = config.get('main', 'SQLITE_URI')
app.config['WTF_CSRF_SECRET_KEY'] = config.get('main', 'WTF_CSRF_SECRET_KEY')
app.config['SECRET_KEY'] = config.get('main', 'SECRET_KEY')
shared.whitelisted_devices = ast.literal_eval(config.get('main', 'WHITELISTED_DEVICES'))
# pushover_user_key = config.get('main', 'PUSHOVER_USER_KEY')
# pushover_api_token = config.get('main', 'PUSHOVER_APP_TOKEN')

app.debug = True

# http://librelist.com/browser//flask/2014/10/23/runtimeerror-application-not-registered-on-db-and-no-application-context/#51ac718f878f7a3eef552411bdf2c597
shared.db.init_app(app)
shared.db.app = app

babel = Babel(app)

CsrfProtect(app)

with app.app_context():
    # Extensions like Flask-SQLAlchemy now know what the "current" app
    # is while within this block. Therefore, you can now run........
    shared.db.create_all()

# start sniffing traffic
if DEBUG is not True:
    sniffer = wifi_monitor.sniff_thread.Sniff_Thread(config.get('main', 'CACHE_SIZE'),
                                                     config.get('main', 'CACHE_TIMEOUT_SECONDS'))
    sniffer.start()


def add_device_to_whitelist(mac):
    shared.whitelisted_devices.appent(mac)
    config.set('main', 'WHITELISTED_DEVICES', shared.whitelisted_devices)
    configFile = open('properties.conf', 'w')
    config.write(configFile)
    configFile.close()


@app.route('/', defaults={'page': 1})
@app.route('/page/<int:page>', methods=['GET', 'POST'])
def index(page):
    if request.method == "POST":
        form = EditProbeRequestForm(request.form)
        flash("POSTED MAC: " + form.mac_address.data + " ALIAS: " + form.alias.data)
        prs = models.ProbeRequest.query.filter_by(src=form.mac_address.data).all()
        for pr in prs:
            pr.alias = form.alias.data.strip()
            shared.db.session.add(pr)
        shared.db.session.commit()
        shared.db.session.flush()
        return redirect('/page/' + str(page))

    # get total number of probe requests
    total_probe_requests = shared.db.session.query(func.count(models.ProbeRequest.id)).scalar()
    # only grab the number of probe requests necessary for the page requested
    probe_requests = models.ProbeRequest.query.order_by(models.ProbeRequest.timestamp.asc()).offset(
        (page - 1) * 200).limit(
        200).all()
    pagination = Pagination(page=page, total=total_probe_requests, search=False, record_name="probe requests",
                            per_page=200, bs_version=3, format_total=True, format_number=True)
    form = EditProbeRequestForm()

    return render_template('index.html', probe_requests=probe_requests,
                           pagination=pagination, form=form, page=page)


def shutdown_server():
    shutdown_func = request.environ.get('werkzeug.server.shutdown')
    if shutdown_func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    shutdown_func()


@app.route('/shutdown')
def shutdown():
    if DEBUG is not True:
        sniffer.stop()
        sniffer.join(10000)
    shutdown_server()
    return 'Server shutting down...'


@app.route('/device_list')
def device_list():
    # get a distinct list of devices with the mac address and the alias
    distinct_devices = shared.db.session.query(models.ProbeRequest.src, models.ProbeRequest.alias).distinct().all()
    dev_count = {}
    # for each device:
    #   get the number of times the device appears in the DB
    #   the timestamp the last time the device was seen
    for dev in distinct_devices:
        count = shared.db.session.query(models.ProbeRequest).filter(models.ProbeRequest.src.like(dev.src)).count()
        last_seen = shared.db.session.query(models.ProbeRequest.timestamp).filter(
            models.ProbeRequest.src.like(dev.src)).order_by(desc(models.ProbeRequest.timestamp)).first()[0]
        dev_count[dev] = (count, last_seen)
    return render_template('device_list.html', dev_count=dev_count)


@app.route('/device_history', methods=['GET', 'POST'])
def device_history():
    # mac_addresses = models.ProbeRequest.query.filter_by(src=form.mac_address.data).all()

    # get a distinct list of devices with the mac address and the alias
    distinct_devices = shared.db.session.query(models.ProbeRequest.src, models.ProbeRequest.alias).distinct().all()

    if request.method == "POST":
        data = request.form
        device_history = models.ProbeRequest.query.filter_by(src=data['mac']).all()
        return render_template('device_history.html', distinct_devices=distinct_devices, dev_history=device_history)

    return render_template('device_history.html', distinct_devices=distinct_devices)


@app.route('/refresh_probe_requests')
def refresh_probe_requests():
    probe_requests = models.ProbeRequest.query.order_by(models.ProbeRequest.timestamp.desc()).all()
    return jsonify(probe_requests=[pr.serialize() for pr in probe_requests])


@app.template_filter('datetime')
def format_timestamp(value, format='medium'):
    return format_datetime(value, format="EE dd.MM.y HH:mm")


if __name__ == "__main__":
    try:
        app.run('0.0.0.0', 5000, use_reloader=False)
    except KeyboardInterrupt:
        print "Caught ctrl-c"
        if DEBUG is not True:
            sniffer.stop()
