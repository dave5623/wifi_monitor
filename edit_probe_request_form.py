# from flask_wtf import Form
from flask.ext.wtf import Form
from wtforms import StringField, DateField, IntegerField


class EditProbeRequestForm(Form):
    mac_address = StringField("MAC Address")
    device_vendor = StringField("Vendor")
    ssid = StringField("SSID")
    ssi_signal = IntegerField("SSI Signal")
    date = DateField("Date")
    alias = StringField("Alias")
