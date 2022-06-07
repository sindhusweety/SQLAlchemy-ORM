from app import talosdb, app, cache
from flask_user import current_user
from app.lib.url_id_mixin import UrlIdMixin
from app.lib.datafuncs.caches import make_sensor_data_dict
from app.models import model_constants
from datetime import datetime as mydatetime
from datetime import timedelta
from sqlalchemy import text, func, select
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.dialects.postgresql.json import JSONB, JSON

from wtforms import Form, TextAreaField, FileField, HiddenField
import architect
from flask_sqlalchemy_caching import FromCache
from sqlalchemy.ext.mutable import MutableDict, MutableList
from collections import OrderedDict
from app.lib.parsers.wifi.encryption import ap_risk_score_detail
import binascii


# Wireless Network Database
class WiFiNetwork(talosdb.Model, UrlIdMixin):
    __tablename__ = 'wifi_networks'
    id = talosdb.Column(talosdb.Integer, primary_key=True)
    essid = talosdb.Column(talosdb.Unicode, server_default=u'', index=True)
    customer_id = talosdb.Column(talosdb.Integer, talosdb.ForeignKey('customers.id', ondelete='SET NULL'))
    client_count_placeholder = talosdb.Column(talosdb.Integer, server_default='0')
    bssid_count_placeholder = talosdb.Column(talosdb.Integer, server_default='0')
    meta = talosdb.Column(JSONB)

    # Timestamps
    created = talosdb.Column(talosdb.DateTime, server_default=text('CURRENT_TIMESTAMP'))
    updated = talosdb.Column(talosdb.DateTime, onupdate=mydatetime.utcnow)

    def __init__(self, **kwargs):
        self.essid = kwargs.get('essid')
        self.customer_id = kwargs.get('customer_id')
        self.bssid_count_placeholder = kwargs.get('bssid_count_placeholder', 0)
        self.client_count_placeholder = kwargs.get('client_count_placeholder', 0)
        self.meta = kwargs.get('meta')
        self.created = mydatetime.utcnow()
        self.updated = mydatetime.utcnow()

    @hybrid_property
    def client_count_current(self, minutes=10):
        last_30m = mydatetime.utcnow() - timedelta(minutes=minutes)
        q = ClientsAps.query.filter(ClientsAps.last_seen >= last_30m)
        q = q.join(AccessPoint, ClientsAps.ap_id == AccessPoint.id).filter(AccessPoint.essid == self.essid)
        q = q.filter(AccessPoint.customer_id == self.customer_id).with_entities(ClientsAps.id).options(FromCache(cache))
        return q.count()

    @client_count_current.expression
    def client_count_current(cls):
        return cls.client_count_placeholder

    @hybrid_property
    def bssid_count_current(self):
        if self.essid == "UNCONNECTED CLIENTS":
            return 0

        q = AccessPoint.query.filter_by(
            customer_id=self.customer_id, essid=self.essid
        ).with_entities(AccessPoint.id).options(FromCache(cache))
        return q.count()

    @bssid_count_current.expression
    def bssid_count_current(cls):
        return cls.bssid_count_placeholder


# Manufacturer OUI Database
class WiFiManufacturer(talosdb.Model, UrlIdMixin):
    __tablename__ = 'wifimanufacturers'
    id = talosdb.Column(talosdb.Integer, primary_key=True)
    oui = talosdb.Column(talosdb.String(8), server_default='', unique=True, index=True)
    manuf = talosdb.Column(talosdb.Unicode, server_default=u'', index=True)
    address = talosdb.Column(talosdb.Unicode, server_default=u'')

    def __init__(self, **kwargs):
        self.oui = kwargs.get('oui')
        self.manuf = kwargs.get('manuf')
        self.address = kwargs.get('address')


class APTrustLevel(talosdb.Model, UrlIdMixin):
    """
    AP Trust level definitions
    """
    __tablename__ = 'ap_trust_levels' #new table(ap_trustlevel_similarity) -connect id, ap_trustlevel_id, similaruty)

    id = talosdb.Column(talosdb.Integer(), primary_key=True)
    customer_id = talosdb.Column(talosdb.Integer, talosdb.ForeignKey('customers.id'))
    trust_level = talosdb.Column(talosdb.Integer)
    __table_args__ = (talosdb.Index('ix_trust_levels_customer', 'customer_id', 'trust_level', unique=True),)

    name = talosdb.Column(talosdb.Unicode)
    options = talosdb.Column(JSONB)             # holder of options:
    trust_level_name = talosdb.Column(talosdb.VARCHAR)
    # ok_to_connect: list of client group numbers allowed to connect
    # unapproved_client_severity: event severity when unapproved client connects to AP
    # auto_connect_setting: client group to assign new connected clients to
    # essid_similarity_assignment: trust level to assign similar ESSID matches
    # essid_severity: event severity when similar ESSID matches are found
    # color_code: color code for the UI
    # ap_timing: how long before reporting the device missing

    def __init__(self, **kwargs):
        self.customer_id = kwargs.get('customer_id')
        self.trust_level = kwargs.get('trust_level')
        self.name = kwargs.get('name')
        self.options = kwargs.get('options')
        self.trust_level_name = kwargs.get('trust_level_name')

class APTrustlevel_Similarity(talosdb.Model, UrlIdMixin):
    """
    AP Trust level Similarity definitions
    """
    __tablename__ = 'ap_trust_levels_similarity'
    id = talosdb.Column(talosdb.Integer(), primary_key=True)
    ap_trust_level_id =  talosdb.Column(talosdb.Integer, talosdb.ForeignKey('ap_trust_levels.id', ondelete='SET NULL'))
    similarity = talosdb.Column(JSON)

    def __init__(self, **kwargs):
        self.ap_trust_level_id = kwargs.get('ap_trust_level_id')
        self.similarity = kwargs.get('similarity')

# An AccessPoint represents a wireless access point
class AccessPoint(talosdb.Model, UrlIdMixin):
    __tablename__ = 'accesspoints'
    id = talosdb.Column(talosdb.BigInteger, primary_key=True)
    customer_id = talosdb.Column(talosdb.Integer, talosdb.ForeignKey('customers.id', ondelete='SET NULL'))
    bssid = talosdb.Column(talosdb.String(model_constants['BSSID_LEN']), server_default='', nullable=False, index=True)
    band = talosdb.Column(talosdb.Float)            # spectrum frequency band in GHz - 2.4, 5, 6
    __table_args__ = (
        talosdb.Index('ix_aps_customer_bssid_band', 'customer_id', 'bssid', 'band', unique=True),
    )

    wrat_id = talosdb.Column(talosdb.Integer, talosdb.ForeignKey('wrats.id', ondelete='SET NULL'), index=True)

    name = talosdb.Column(talosdb.Unicode(model_constants['NAME_LEN']), server_default=u'Unknown', index=True)
    trust_level = talosdb.Column(talosdb.Integer, server_default='50', index=True)
    market = talosdb.Column(talosdb.Unicode(model_constants['NAME_LEN']), server_default=u'', index=True)
    essid = talosdb.Column(talosdb.Unicode, server_default=u'', index=True)
    essid_hidden = talosdb.Column(talosdb.Boolean, server_default='0')
    max_rate = talosdb.Column(talosdb.Float, server_default='0.0')
    manuf = talosdb.Column(talosdb.Unicode(model_constants['NAME_LEN']), server_default=u'', index=True)
    channel = talosdb.Column(talosdb.Float, server_default='0', index=True)
    observed_channel = talosdb.Column(talosdb.Float, server_default='0', index=True)
    supported_channels = talosdb.Column(talosdb.UnicodeText, server_default='')
    supported_modulation = talosdb.Column(talosdb.UnicodeText, server_default='')
    country = talosdb.Column(talosdb.UnicodeText, server_default='')
    frequency = talosdb.Column(talosdb.Float, server_default='0.0')
    bandwidth = talosdb.Column(talosdb.Integer, server_default='0')
    packets_total = talosdb.Column(talosdb.Integer, server_default='0')
    last_signal_dbm = talosdb.Column(talosdb.Integer, server_default='0', index=True)
    last_noise_dbm = talosdb.Column(talosdb.Integer, server_default='0')
    last_signal_rssi = talosdb.Column(talosdb.Integer, server_default='0')
    last_noise_rssi = talosdb.Column(talosdb.Integer, server_default='0')
    min_signal_dbm = talosdb.Column(talosdb.Integer, server_default='0')
    min_noise_dbm = talosdb.Column(talosdb.Integer, server_default='0')
    min_signal_rssi = talosdb.Column(talosdb.Integer, server_default='0')
    min_noise_rssi = talosdb.Column(talosdb.Integer, server_default='0')
    max_signal_dbm = talosdb.Column(talosdb.Integer, server_default='0')
    max_noise_dbm = talosdb.Column(talosdb.Integer, server_default='0')
    max_signal_rssi = talosdb.Column(talosdb.Integer, server_default='0')
    max_noise_rssi = talosdb.Column(talosdb.Integer, server_default='0')
    encryption = talosdb.Column(talosdb.Unicode, server_default=u'', index=True)
    authentication = talosdb.Column(talosdb.Unicode, server_default=u'', index=True)
    wps_capable = talosdb.Column(talosdb.Boolean)
    wps_data = talosdb.Column(JSONB)
    passpoint_enabled = talosdb.Column(talosdb.Boolean)
    passpoint_data = talosdb.Column(JSONB)
    risk_score = talosdb.Column(talosdb.Integer, index=True)
    interrogations = talosdb.relationship('InterrogationRequest', backref='accesspoint', lazy='dynamic')

    # AP Data/IE information
    eap_types = talosdb.Column(JSONB)
    pmf_required = talosdb.Column(talosdb.Boolean)
    pmf_capable = talosdb.Column(talosdb.Boolean)
    adv_freqs = talosdb.Column(talosdb.ARRAY(talosdb.Float))
    vht_capable = talosdb.Column(talosdb.Boolean)
    vht_data = talosdb.Column(talosdb.Unicode)
    lldp_info = talosdb.Column(MutableDict.as_mutable(JSONB))
    probe_response_data = talosdb.Column(MutableDict.as_mutable(JSONB))
    beacon_data = talosdb.Column(MutableDict.as_mutable(JSONB))

    # Timestamps
    created = talosdb.Column(talosdb.DateTime, server_default=text("CURRENT_TIMESTAMP"))
    updated = talosdb.Column(talosdb.DateTime, onupdate=mydatetime.utcnow)
    last_seen = talosdb.Column(talosdb.DateTime, index=True)

    misc_attribs = talosdb.Column(MutableDict.as_mutable(JSONB))
    latitude = talosdb.Column(talosdb.Float)
    longitude = talosdb.Column(talosdb.Float)
    altitude = talosdb.Column(talosdb.Float)

    # has this been verified
    verified = talosdb.Column(talosdb.Boolean)

    # Relationships
    raw_accesspoints = talosdb.relationship('RawAccessPoint', backref='accesspoint', lazy='dynamic')
    raw_clients = talosdb.relationship('RawClient', backref='accesspoint', lazy='dynamic')
    events = talosdb.relationship('Event', backref='accesspoint', lazy='dynamic')
    x509_cert = talosdb.relationship('X509Certs', backref='accesspoint', lazy='dynamic')
    wpahandshake = talosdb.relationship('WPAHandshake', backref='accesspoint', lazy='dynamic')

    tags = talosdb.relationship(
        'Tag', secondary='accesspoint_tags',
        backref=talosdb.backref('accesspoints', lazy='dynamic')
    )
    trust_level_name = talosdb.Column(talosdb.VARCHAR)


    def __init__(self, **kwargs):
        self.name = kwargs.get('name', '')
        self.trust_level = kwargs.get('trust_level', 50)
        self.market = kwargs.get('market', u'Home/Office')
        self.tags = kwargs.get('tags', [])
        self.customer_id=kwargs.get('customer_id')
        self.wrat_id = kwargs.get('wrat_id')
        self.bssid = kwargs.get('bssid', '').upper()
        self.band = kwargs.get('band', 0)
        self.essid = kwargs.get('essid', '')
        self.essid_hidden = bool(kwargs.get('essid_hidden', False))
        self.max_rate = kwargs.get('max_rate', 0)
        self.manuf = kwargs.get('manuf')
        self.channel = int(kwargs.get('channel', 0))
        self.observed_channel = kwargs.get('observed_channel', 0)
        self.supported_channels = kwargs.get('supported_channels', '{}')
        self.supported_modulation = kwargs.get('supported_modulation')
        self.country = kwargs.get('country', '')
        self.frequency = kwargs.get('frequency', 0)
        self.packets_total = kwargs.get('packets_total', 0)
        self.last_signal_dbm = kwargs.get('last_signal_dbm', 0)
        self.last_noise_dbm = kwargs.get('last_noise_dbm', 0)
        self.last_signal_rssi = kwargs.get('last_signal_rssi', 0)
        self.last_noise_rssi = kwargs.get('last_noise_rssi', 0)
        self.min_signal_dbm = kwargs.get('min_signal_dbm', 0)
        self.min_noise_dbm = kwargs.get('min_noise_dbm', 0)
        self.min_signal_rssi = kwargs.get('min_signal_rssi', 0)
        self.min_noise_rssi = kwargs.get('min_noise_rssi', 0)
        self.max_signal_dbm = kwargs.get('max_signal_dbm', 0)
        self.max_noise_dbm = kwargs.get('max_noise_dbm', 0)
        self.max_signal_rssi = kwargs.get('max_signal_rssi', 0)
        self.max_noise_rssi = kwargs.get('max_noise_rssi', 0)
        encryption = kwargs.get('encryption', [])
        if isinstance(encryption, list):
            encryption_string = ','.join(encryption)
        else:
            encryption_string = encryption
        self.encryption = encryption_string
        self.authentication = kwargs.get('authentication', [])
        authentication = kwargs.get('authentication', [])
        if isinstance(authentication, list):
            authentication_string = ','.join(authentication)
        else:
            authentication_string = authentication
        self.authentication = authentication_string
        self.wps_capable = bool(kwargs.get('wps_capable', False))
        self.wps_data = kwargs.get('wps_data', {})
        self.passpoint_enabled = bool(kwargs.get('passpoint_enabled', False))
        self.passpoint_data = kwargs.get('passpoint_data', {})
        self.eap_types = kwargs.get('eap_types', "")
        self.vht_capable = kwargs.get('vht_capable')
        self.vht_data = kwargs.get('vht_data')
        self.lldp_info = kwargs.get('lldp_info')
        self.probe_response_data = kwargs.get('probe_response_data', {})
        self.beacon_data = kwargs.get('beacon_data', {})
        self.adv_freqs = kwargs.get('adv_freqs')
        self.pmf_required = kwargs.get('pmf_required', False)
        self.pmf_capable = kwargs.get('pmf_capable', False)
        self.created = mydatetime.utcnow()
        self.updated = mydatetime.utcnow()
        self.last_seen = mydatetime.utcnow()
        self.verified = kwargs.get('verified', False)
        self.misc_attribs = kwargs.get('misc_attribs', {})
        self.risk_score = ap_risk_score_detail(encryption_string, authentication_string, self.wps_capable, self.pmf_capable, self.pmf_required)['score']
        self.latitude = kwargs.get('latitude', 0)
        self.longitude = kwargs.get('longitude', 0)
        self.altitude = kwargs.get('altitude', 0)
        self.trust_level_name = kwargs.get('trust_level_name')

    @staticmethod
    def add_column(engine, column):
        column_name = column.compile(dialect=engine.dialect)
        column_type = column.type.compile(engine.dialect)
        engine.execute('ALTER TABLE %s ADD COLUMN %s %s' % (AccessPoint.__tablename__, column_name, column_type))

    def __getitem__(self, item):
        return getattr(self, item)

    @hybrid_property
    def client_count(self):
        # Count the number of clients based on the Many-to-Many relationship with ClientsAps
        last_30m = mydatetime.utcnow() - timedelta(minutes=30)
        count_q = self.clients.filter(ClientsAps.last_seen >= last_30m).statement.with_only_columns([func.count()]).order_by(None)
        count = self.clients.session.execute(count_q).scalar()
        return count

    @client_count.expression
    def client_count(cls):
        # Expression for querying client_count
        last_30m = mydatetime.utcnow() - timedelta(minutes=30)
        return select([func.count(ClientsAps.id)]).where(ClientsAps.ap_id==cls.id).where(ClientsAps.last_seen >= last_30m).label('client_count')

    @hybrid_property
    def manufacturer(self):
        if not isinstance(self.bssid, str):
            return self.manuf
        m = WiFiManufacturer.query.filter_by(oui=self.bssid[0:8].upper()).options(FromCache(cache)).first()
        if not m:
            return self.manuf
        return m.manuf

    @manufacturer.expression
    def manufacturer(self):
        return WiFiManufacturer.manuf

    @hybrid_property
    def wpa_handshakes(self):
        return self.wpahandshake.count()

    @wpa_handshakes.expression
    def wpa_handshakes(cls):
        return select([func.count(WPAHandshake.id)]).where(WPAHandshake.accesspoint_id==cls.id).label('wpa_handshakes')

    @hybrid_property
    def tags_query(self):
        return AccessPointTags.query.filter(AccessPointTags.ap_id == self.id)

    @tags_query.expression
    def tags_query(cls):
        return AccessPoint.tags_query

    @hybrid_property
    def trust_level_record(self):
        tl = APTrustLevel.query.filter(
            APTrustLevel.trust_level == self.trust_level, APTrustLevel.customer_id == self.customer_id
        ).options(FromCache(cache)).first()
        if not tl:
            return [50, 'Undefined', 'black']
        return [tl.trust_level, tl.name, tl.options['color_code']]

    @trust_level_record.expression
    def trust_level_record(cls):
        return AccessPoint.trust_level_record

    @hybrid_property
    def latest_x509cert(self):
        return X509Certs.query.filter_by(accesspoint_id=self.id).order_by(X509Certs.created.desc()).options(FromCache(cache)).first()

    @latest_x509cert.expression
    def x509_subject(cls):
        return

    @hybrid_property
    def calculate_risk_score(self):
        return ap_risk_score_detail(
            self.encryption, self.authentication, self.wps_capable, self.pmf_capable, self.pmf_required
        )['score']

    @hybrid_property
    def risk_score_details(self):
        return ap_risk_score_detail(
            self.encryption, self.authentication, self.wps_capable, self.pmf_capable, self.pmf_required
        )

    #@hybrid_property
    #def bssid_count(self):
    #    # Fake field for networks list (func.count(AccessPoint.bssid))
    #    return self.bssid

    #@hybrid_property
    #def essid_client_count(self):
    #    # Fake field for networks list (func.sum(AccessPoint.client_count))
    #    return self.client_count

    def format_json(self) -> dict:
        tags = {}
        for k in [_.dict() for _ in self.tags]:
            tags[k['category']] = k['name']
        d = OrderedDict()
        d['essid'] = self.essid.encode('utf-8') if self.essid else ''
        d['hidden'] = self.essid_hidden
        d['bssid'] = self.bssid
        d['manufacturer'] = self.manufacturer.encode('utf-8') if self.manufacturer else ''
        d['channel'] = int(self.channel)
        d['signal'] = self.last_signal_dbm
        d['trust_level'] = self.trust_level
        d['risk_score'] = self.risk_score
        d['configuration'] = {
            'encryption': self.encryption or 'None',
            'authentication': self.authentication,
            'supported_channels': self.supported_channels,
            'vht_capable': self.vht_capable,
            'pmf_capable': self.pmf_capable,
            'pmf_required': self.pmf_required,
            'wps': {
                'capable': self.wps_capable,
                'data': self.wps_data,
            },
            'hs20': {
                'enabled': self.passpoint_enabled,
                'data': self.passpoint_data,
            },
            'eap_types': self.get_eap_types(),
        }
        d['sensor_name'] = self.wrats.shortname
        d['sensor_url_id'] = self.wrats.url_id()
        if getattr(self, 'misc_attribs'):
            d['ap_mode'] = self.misc_attribs.get('station_type', 'Infrastructure')
        else:
            d['ap_mode'] = 'Infrastructure'
        d['market'] = self.market
        d['vendor_tag'] = tags.get('Vendor', '')
        d['device_tag'] = tags.get('Device', '')
        d['product_tag'] = tags.get('Product', '')
        d['location_tag'] = tags.get('Location', '')
        d['first_seen'] = self.created.isoformat()
        d['last_seen'] = self.last_seen.isoformat()
        d['latitude'] = self.latitude
        d['longitude'] = self.longitude
        d['url_id'] = self.url_id()
        return d

    @cache.memoize(60)
    def get_sensor_data(self):
        return make_sensor_data_dict(self.wrat_id)

    def get_eap_types(self):
        eap_types = []
        if isinstance(self.eap_types, list):
            for eap in self.eap_types:
                if isinstance(eap, list) and len(eap) == 2:
                    eap_types.append('{}: {}'.format(eap[1], model_constants['EAP_TYPES'].get(str(eap[1]), 'Unknown')))
            return eap_types

    @staticmethod
    def get_ap_rec(customer_id=None, bssid=None, band=0.0, channel=0, ap_id=None, ap_url_id=None, fields=[], filters=[]):
        """Returns an AccessPoint record based on specific criteria

        :param customer_id: Customer identifier number
        :param bssid: BSS identifier number
        :param band: Frequency band (2.4, 5, 6 or 0 if not set)
        :param channel: Channel to use if no frequency band
        :param ap_id: Specific record ID number - ignores everything else
        :param ap_url_id: Specific record ID as url_id - turns into ap_id
        :param fields: list of fields to limit in return
        :param filters: list of SQLAlchemy filters to apply
        :return AccessPoint: An AccessPoint record or None if not found
        """
        # app.logger.debug(f'bssid={bssid}, band={band}, channel={channel}')
        ap_query = AccessPoint.query.options(FromCache(cache))
        if fields and isinstance(fields, list):
            ap_query = ap_query.with_entities(*fields)

        # Check for ap_id / ap_url_id
        if ap_url_id:
            ap_id = AccessPoint.decode_url_id(ap_url_id, current_user)
        if ap_id:
            return ap_query.get(ap_id)

        # ensure customer_id and bssid is set
        if not customer_id:
            app.logger.error('No customer_id sent for get_ap_rec')
            return None
        if not bssid:
            app.logger.error('No bssid sent for get_ap_rec')
            return None

        for filter in filters:
            ap_query = ap_query.filter(filter)

        ap_query = ap_query.filter(AccessPoint.bssid == bssid, AccessPoint.customer_id == customer_id)
        ap_rec = ap_query.filter(AccessPoint.band == band).first()
        if ap_rec:
            # found record using the band field .. return it
            return ap_rec

        # Search for an AP record that doesn't have a band assigned. Use the channel range to search instead
        try:
            channel = int(channel)
        except TypeError:
            app.logger.error(f'Channel {channel} cannot be converted to integer')
            return None
        if channel in model_constants['WIFI_24_CHANNEL']:
            return ap_query.filter(AccessPoint.channel.in_(model_constants['WIFI_24_CHANNEL'])).first()
        elif channel in model_constants['WIFI_5_CHANNEL']:
            return ap_query.filter(AccessPoint.channel.in_(model_constants['WIFI_5_CHANNEL'])).first()

        return ap_query.first()


# many-to-many relationship between APs and Tags
class AccessPointTags(talosdb.Model):
    __tablename__ = 'accesspoint_tags'
    id = talosdb.Column(talosdb.Integer(), primary_key=True)
    tag_id = talosdb.Column(talosdb.Integer(), talosdb.ForeignKey('tags.id', ondelete='CASCADE'), nullable=False)
    tag = talosdb.relationship('Tag', backref='accesspoint_tags')
    ap_id = talosdb.Column(talosdb.Integer(), talosdb.ForeignKey('accesspoints.id', ondelete='CASCADE'), nullable=False)
    accesspoint = talosdb.relationship('AccessPoint', backref='accesspoint_tags')
    assigned_by = talosdb.Column(talosdb.String(), default='ANALYTICS')     # ANALYTICS or USER
    confidence = talosdb.Column(talosdb.Integer())                          # 1 - 100 percentile

    def __init__(self, **kwargs):
        self.tag_id = kwargs.get('tag_id', kwargs.get('ref_id'))
        self.ap_id = kwargs.get('ap_id')
        self.assigned_by = kwargs.get('assigned_by', 'ANALYTICS')
        self.confidence = kwargs.get('confidence', 100)


class APClientMassAssignUploadForm(Form):
    pastecontents = TextAreaField(
        'Paste',
        render_kw={'placeholder': '00:11:22:33:44:55,1\n01:02:03:04:05:06,1\n01:de:ad:be:ef:02,4', 'cols': 140, 'rows': 20}
    )
    filecontents = FileField('CSV File')


class APIsolateUploadForm(Form):
    pastecontents = TextAreaField('Paste')
    filecontents = FileField('CSV File')
    duration = HiddenField('duration')


class APInterrogateUploadForm(Form):
    pastecontents = TextAreaField('Paste')
    filecontents = FileField('CSV File')


class ClientGroup(talosdb.Model, UrlIdMixin):
    __tablename__ = 'client_groups'
    __table_args__ = (talosdb.Index('ix_client_groupnum_customers', 'customer_id', 'number', unique=True),)

    id = talosdb.Column(talosdb.Integer(), primary_key=True)
    customer_id = talosdb.Column(talosdb.Integer, talosdb.ForeignKey('customers.id', ondelete='SET NULL'))
    number = talosdb.Column(talosdb.Integer)
    name = talosdb.Column(talosdb.Unicode)
    risk_multiplier = talosdb.Column(talosdb.Integer)
    color_code = talosdb.Column(talosdb.String)  # hex or string color code
    event_severity = talosdb.Column(talosdb.Integer)
    clients = talosdb.relationship('Client', backref='client_groups', lazy='dynamic')

    def __init__(self, **kwargs):
        self.customer_id = kwargs.get('customer_id')
        self.number = kwargs.get('number')
        self.name = kwargs.get('name', 'Undefined')
        self.risk_multiplier = kwargs.get('risk_multiplier', 1)
        self.color_code = kwargs.get('color_code', 'green')
        self.event_severity = kwargs.get('event_severity', 1)


# A Client represents a wireless device (e.g. Cell phone, Tablet, etc)
class Client(talosdb.Model, UrlIdMixin):
    __tablename__ = 'clients'
    id = talosdb.Column(talosdb.BigInteger, primary_key=True)
    customer_id = talosdb.Column(talosdb.Integer, talosdb.ForeignKey('customers.id', ondelete='SET NULL'))
    macaddress = talosdb.Column(talosdb.String(model_constants['MAC_ADDRESS_LEN']), server_default='', nullable=False, index=True)
    __table_args__ = (talosdb.Index('ix_stations_customer_macaddress', 'customer_id', 'macaddress', unique=True),)

    wrat_id = talosdb.Column(talosdb.Integer, talosdb.ForeignKey('wrats.id', ondelete='SET NULL'), index=True)

    name = talosdb.Column(talosdb.Unicode(model_constants['NAME_LEN']), server_default='', index=True)
    risk_level = talosdb.Column(talosdb.Integer, server_default='0', index=True)
    group_id = talosdb.Column(talosdb.Integer, talosdb.ForeignKey('client_groups.id', ondelete='SET NULL'))
    market = talosdb.Column(talosdb.Unicode(model_constants['NAME_LEN']), server_default=u'', index=True) 
    manuf = talosdb.Column(talosdb.Unicode(model_constants['NAME_LEN']), server_default=u'', index=True)
    channel = talosdb.Column(talosdb.Float, server_default='0', index=True)
    packets_total = talosdb.Column(talosdb.Integer, server_default='0')
    max_rate = talosdb.Column(talosdb.Float, server_default='0.0')
    supported_channels = talosdb.Column(talosdb.UnicodeText, server_default='')
    country = talosdb.Column(talosdb.UnicodeText, server_default='')
    encryption = talosdb.Column(talosdb.Unicode, server_default=u'', index=True)
    last_signal_dbm = talosdb.Column(talosdb.Integer, server_default='0', index=True)
    last_noise_dbm = talosdb.Column(talosdb.Integer, server_default='0')
    last_signal_rssi = talosdb.Column(talosdb.Integer, server_default='0')
    last_noise_rssi = talosdb.Column(talosdb.Integer, server_default='0')
    min_signal_dbm = talosdb.Column(talosdb.Integer, server_default='0')
    min_noise_dbm = talosdb.Column(talosdb.Integer, server_default='0')
    min_signal_rssi = talosdb.Column(talosdb.Integer, server_default='0')
    min_noise_rssi = talosdb.Column(talosdb.Integer, server_default='0')
    max_signal_dbm = talosdb.Column(talosdb.Integer, server_default='0')
    max_noise_dbm = talosdb.Column(talosdb.Integer, server_default='0')
    max_signal_rssi = talosdb.Column(talosdb.Integer, server_default='0')
    max_noise_rssi = talosdb.Column(talosdb.Integer, server_default='0')
    probes = talosdb.Column(MutableList.as_mutable(talosdb.ARRAY(talosdb.Unicode, dimensions=1)))
    probe_request_data = talosdb.Column(MutableDict.as_mutable(JSONB))

    # Relationships
    probe_ssids = talosdb.relationship(
        'ProbeSSID', secondary='clients_probe_ssids',
        backref=talosdb.backref('clients', lazy='dynamic')
    )
    accesspoints = talosdb.relationship(
        'AccessPoint', secondary='clients_accesspoints',
        backref=talosdb.backref('clients', lazy='dynamic')
    )
    tags = talosdb.relationship(
        'Tag', secondary='client_tags',
        backref=talosdb.backref('clients', lazy='dynamic')
    )

    # Relationships
    raw_clients = talosdb.relationship('RawClient', backref='client', lazy='dynamic')
    events = talosdb.relationship('Event', backref='client', lazy='dynamic')
    x509_cert = talosdb.relationship('X509Certs', backref='client', lazy='dynamic')
    captivity_acceptance_id = talosdb.Column(talosdb.Integer, talosdb.ForeignKey('captivity_acceptance.id', ondelete='SET NULL'))

    # Timestamps
    created = talosdb.Column(talosdb.DateTime, server_default=text("CURRENT_TIMESTAMP"))
    updated = talosdb.Column(talosdb.DateTime, onupdate=mydatetime.utcnow)
    last_seen = talosdb.Column(talosdb.DateTime, index=True)

    misc_attribs = talosdb.Column(MutableDict.as_mutable(JSONB))
    latitude = talosdb.Column(talosdb.Float)
    longitude = talosdb.Column(talosdb.Float)
    altitude = talosdb.Column(talosdb.Float)

    # is_privacy = column_property(True if macaddress[2] in ['2', '6', 'A', 'E'] else False)

    def __init__(self, **kwargs):
        self.customer_id = kwargs.get('customer_id')
        self.wrat_id = kwargs.get('wrat_id')
        self.name = kwargs.get('name', '')
        self.threat_level = kwargs.get('threat_level', 0)
        self.group_id = kwargs.get('group_id')
        self.macaddress = kwargs.get('macaddress', '').upper()
        self.market = kwargs.get('market', u'Home/Office')
        self.tags = kwargs.get('tags', [])
        self.manuf = kwargs.get('manuf')
        self.channel = int(kwargs.get('channel', 0))
        self.packets_total = kwargs.get('packets_total', 0)
        self.max_rate = kwargs.get('max_rate', 0)
        self.observed_channel = kwargs.get('observed_channel', 0)
        self.supported_channels = kwargs.get('supported_channels', 0)
        self.country = kwargs.get('country', 0)
        self.last_signal_dbm = kwargs.get('last_signal_dbm', 0)
        self.last_noise_dbm = kwargs.get('last_noise_dbm', 0)
        self.last_signal_rssi = kwargs.get('last_signal_rssi', 0)
        self.last_noise_rssi = kwargs.get('last_noise_rssi', 0)
        self.min_signal_dbm = kwargs.get('min_signal_dbm', 0)
        self.min_noise_dbm = kwargs.get('min_noise_dbm', 0)
        self.min_signal_rssi = kwargs.get('min_signal_rssi', 0)
        self.min_noise_rssi = kwargs.get('min_noise_rssi', 0)
        self.max_signal_dbm = kwargs.get('max_signal_dbm', 0)
        self.max_noise_dbm = kwargs.get('max_noise_dbm', 0)
        self.max_signal_rssi = kwargs.get('max_signal_rssi', 0)
        self.max_noise_rssi = kwargs.get('max_noise_rssi', 0)
        self.probes = kwargs.get('probes', [])
        self.probe_request_data = kwargs.get('probe_request_data', {})
        self.created = mydatetime.utcnow()
        self.updated = mydatetime.utcnow()
        self.last_seen = mydatetime.utcnow()
        self.misc_attribs = kwargs.get('misc_attribs', {})
        self.latitude = kwargs.get('latitude', 0)
        self.longitude = kwargs.get('longitude', 0)
        self.altitude = kwargs.get('altitude', 0)

    def __getitem__(self, item):
        return getattr(self, item)

    def format_json(self):
        tags = {}
        for k in [_.dict() for _ in self.tags]:
            tags[k['category']] = k['name']

        d = OrderedDict()
        d['macaddress'] = self.macaddress
        d['privacy'] = self.is_privacy
        d['manufacturer'] = self.manufacturer.encode('utf-8') if self.manufacturer else ''
        d['channel'] = self.channel
        d['signal'] = self.last_signal_dbm
        d['probes'] = self.probes
        d['sensor_name'] = self.wrats.shortname
        d['sensor_url_id'] = self.wrats.url_id()
        if getattr(self, 'client_groups'):
            d['client_group'] = self.client_groups.name
        else:
            d['client_group'] = 'Unassigned'
        d['risk_level'] = self.risk_level
        d['vendor_tag'] = tags.get('Vendor', '')
        d['device_tag'] = tags.get('Device', '')
        d['product_tag'] = tags.get('Product', '')
        d['location_tag'] = tags.get('Location', '')
        d['first_seen'] = self.created.isoformat()
        d['last_seen'] = self.last_seen.isoformat()
        d['latitude'] = self.latitude
        d['longitude'] = self.longitude
        d['url_id'] = self.url_id()
        d['ap_history'] = self.get_ap_associations()
        return d

    @cache.memoize(60)
    def get_sensor_data(self):
        return make_sensor_data_dict(self.wrat_id)

    def probe_ssid_count(self):
        if not hasattr(self, 'cached_probe_ssid_count'):
            # Count number of clients_probe_ssids records of this client
            self.cached_probe_ssid_count = ClientsProbeSSIDs.query\
                .filter(ClientsProbeSSIDs.client_id==self.id)\
                .count()
        return self.cached_probe_ssid_count

    @property
    def is_privacy(self):
        if self.macaddress[1:2] in ['2', '6', 'A', 'E']:
            return True
        return False

    @hybrid_property
    def manufacturer(self):
        if self.macaddress[1:2] in ['2', '6', 'A', 'E']:
            return 'Privacy Address'
        m = WiFiManufacturer.query.filter_by(oui=self.macaddress[0:8].upper()).first()
        if not m:
            return self.manuf
        return m.manuf

    @manufacturer.expression
    def manufacturer(cls):
        return WiFiManufacturer.manuf

    @hybrid_property
    def last_accesspoint(self):
        return ClientsAps.query.filter(ClientsAps.client_id == self.id).order_by(ClientsAps.last_seen.desc()).options(FromCache(cache)).first()

    @last_accesspoint.expression
    def last_accesspoint(cls):
        return Client.last_accesspoint

    def get_ap_associations(self):
        """
        Return list of APs the client has associated to from the ClientsAps M2M table.
        :return:
        """
        query_results = AccessPoint.query.join(ClientsAps, AccessPoint.id == ClientsAps.ap_id).\
                                    filter(ClientsAps.client_id == self.id). \
                                    order_by(ClientsAps.last_seen.desc()). \
                                    add_columns(AccessPoint.id,
                                                AccessPoint.bssid,
                                                AccessPoint.essid,
                                                AccessPoint.essid_hidden,
                                                AccessPoint.trust_level,
                                                ClientsAps.last_seen)

        results = []
        for r in query_results.options(FromCache(cache)).yield_per(10):
            results.append({
                'url_id': UrlIdMixin.encode_id(r.id),
                'bssid': r.bssid,
                'essid': r.essid,
                'essid_hidden': r.essid_hidden,
                'trust_level': r.trust_level,
                'last_seen': r.last_seen
            })
        return results

    @hybrid_property
    def tags_query(self):
        return ClientTags.query.filter(ClientTags.client_id == self.id)

    @tags_query.expression
    def tags_query(cls):
        return Client.tags_query
   

# many-to-many relationship between clients and Tags
class ClientTags(talosdb.Model):
    __tablename__ = 'client_tags'
    id = talosdb.Column(talosdb.Integer(), primary_key=True)
    tag_id = talosdb.Column(talosdb.Integer(), talosdb.ForeignKey('tags.id', ondelete='CASCADE'), nullable=False)
    tag = talosdb.relationship('Tag', backref='client_tags')
    client_id = talosdb.Column(talosdb.Integer(), talosdb.ForeignKey('clients.id', ondelete='CASCADE'), nullable=False)
    client = talosdb.relationship('Client', backref='client_tags')
    assigned_by = talosdb.Column(talosdb.String(), default='ANALYTICS')     # ANALYTICS or USER
    confidence = talosdb.Column(talosdb.Integer())                          # 1 - 100 percentile

    def __init__(self, **kwargs):
        self.tag_id = kwargs.get('tag_id', kwargs.get('ref_id'))
        self.client_id = kwargs.get('client_id')
        self.assigned_by = kwargs.get('assigned_by', 'ANALYTICS')
        self.confidence = kwargs.get('confidence', 100)


# many-to-many relationship between clients and access points
class ClientsAps(talosdb.Model):
    __tablename__ = 'clients_accesspoints'
    id = talosdb.Column(talosdb.Integer(), primary_key=True)
    ap_id = talosdb.Column(talosdb.Integer(), talosdb.ForeignKey('accesspoints.id', ondelete='CASCADE'), nullable=False)
    accesspoint = talosdb.relationship('AccessPoint', backref='clients_aps')
    client_id = talosdb.Column(talosdb.Integer(), talosdb.ForeignKey('clients.id', ondelete='CASCADE'), nullable=False)
    client = talosdb.relationship('Client', backref='clients_aps')
    last_seen = talosdb.Column(talosdb.DateTime, server_default=text("CURRENT_TIMESTAMP"))
    __table_args__ = (
        talosdb.Index('ix_ap_id', 'ap_id'),
        talosdb.Index('ix_client_id', 'client_id'),
        talosdb.Index('ix_clients_accesspoints_lastseen', last_seen.desc())
    )

    def __init__(self, **kwargs):
        self.ap_id = kwargs.get('ap_id')
        self.client_id = kwargs.get('client_id')
        self.last_seen = kwargs.get('last_seen', mydatetime.utcnow())


# A ProbeSSID object represents an SSID as observed from clients broadcasting ProbeRequest packets
class ProbeSSID(talosdb.Model):
    """
    Collection of probe strings and associated clients
    """
    __tablename__ = 'probe_ssids'
    id = talosdb.Column(talosdb.Integer, primary_key=True)
    ssid = talosdb.Column(talosdb.Unicode, server_default=u'', nullable=False, unique=True)

    # Timestamps
    created = talosdb.Column(talosdb.DateTime, server_default=text("CURRENT_TIMESTAMP"))
    updated = talosdb.Column(talosdb.DateTime, onupdate=mydatetime.utcnow)

    def __init__(self, ssid=None):
        self.ssid = ssid

    # def __repr__(self):
    #     return self.ssid

    def serialize(self):
        return dict(ssid=self.ssid)


# many-to-many relationship between probe_ssids and clients
class ClientsProbeSSIDs(talosdb.Model):
    __tablename__ = 'clients_probe_ssids'
    id = talosdb.Column(talosdb.Integer(), primary_key=True)
    client_id = talosdb.Column(talosdb.Integer(), talosdb.ForeignKey('clients.id', ondelete='CASCADE'), nullable=False)
    probe_ssid_id = talosdb.Column(talosdb.Integer(), talosdb.ForeignKey('probe_ssids.id', ondelete='CASCADE'), nullable=False)
    last_seen = talosdb.Column(talosdb.DateTime, server_default=text("CURRENT_TIMESTAMP"))

    def __init__(self, **kwargs):
        self.client_id = kwargs.get('client_id')
        self.probe_ssid_id = kwargs.get('probe_ssid_id')
        self.last_seen = mydatetime.utcnow()


@architect.install('partition', type='range', subtype='date', constraint='month', column='created', orm='sqlalchemy', db=app.config['SQLALCHEMY_DATABASE_URI'])
class RawAccessPoint(talosdb.Model, UrlIdMixin):
    """
    """
    __tablename__ = 'raw_accesspoints'
    id = talosdb.Column(talosdb.Integer, primary_key=True)
    accesspoint_id = talosdb.Column(talosdb.Integer, talosdb.ForeignKey('accesspoints.id', ondelete='SET NULL'))
    wrat_id = talosdb.Column(talosdb.Integer, talosdb.ForeignKey('wrats.id', ondelete='SET NULL'))
    __table_args__ = (talosdb.Index('ix_raw_accesspoints_created_apid', 'created', 'accesspoint_id'),)

    essid = talosdb.Column(talosdb.Unicode, server_default='')
    essid_hidden = talosdb.Column(talosdb.Boolean, server_default='0')
    max_rate = talosdb.Column(talosdb.Float, server_default='0.0')
    channel = talosdb.Column(talosdb.Float, server_default='0.0')
    signal_dbm = talosdb.Column(talosdb.Integer, server_default='0')
    noise_dbm = talosdb.Column(talosdb.Integer, server_default='0')
    signal_rssi = talosdb.Column(talosdb.Integer, server_default='0')
    noise_rssi = talosdb.Column(talosdb.Integer, server_default='0')
    encryption = talosdb.Column(talosdb.Unicode, server_default='')
    authentication = talosdb.Column(talosdb.Unicode)
    wps_capable = talosdb.Column(talosdb.Boolean)
    wps_data = talosdb.Column(JSONB)
    pmf_capable = talosdb.Column(talosdb.Boolean)
    pmf_required = talosdb.Column(talosdb.Boolean)
    frequency = talosdb.Column(talosdb.Integer)
    country = talosdb.Column(talosdb.Unicode)
    observed_channel = talosdb.Column(talosdb.Integer)
    supported_channels = talosdb.Column(talosdb.Unicode)
    supported_modulation = talosdb.Column(talosdb.Unicode)
    verified = talosdb.Column(talosdb.Boolean)
    latitude = talosdb.Column(talosdb.Float)
    longitude = talosdb.Column(talosdb.Float)
    altitude = talosdb.Column(talosdb.Float)
    misc_attribs = talosdb.Column(MutableDict.as_mutable(JSONB))
    probe_response_data = talosdb.Column(MutableDict.as_mutable(JSONB))
    beacon_data = talosdb.Column(MutableDict.as_mutable(JSONB))

    # Timestamps
    created = talosdb.Column(talosdb.DateTime, server_default=text("CURRENT_TIMESTAMP"))

    def __init__(self, **kwargs):
        self.accesspoint_id = kwargs.get('accesspoint_id')
        self.wrat_id = kwargs.get('wrat_id')
        self.essid = kwargs.get('essid')
        self.essid_hidden = kwargs.get('essid_hidden')
        self.max_rate = kwargs.get('max_rate')
        self.channel = int(kwargs.get('channel', 0))
        self.signal_dbm = kwargs.get('signal_dbm')
        self.noise_dbm = kwargs.get('noise_dbm')
        self.signal_rssi = kwargs.get('signal_rssi')
        self.noise_rssi = kwargs.get('noise_rssi')
        self.encryption = kwargs.get('encryption')
        self.authentication = kwargs.get('authentication')
        self.wps_capable = kwargs.get('wps_capable', False)
        self.wps_data = kwargs.get('wps_data', {})
        self.pmf_capable = kwargs.get('pmf_capable', False)
        self.pmf_required = kwargs.get('pmf_required', False)
        self.country = kwargs.get('country')
        self.observed_channel = kwargs.get('observed_channel', 0)
        self.supported_channels = kwargs.get('supported_channels', "")
        self.supported_modulation = kwargs.get('supported_modulation', "")
        self.frequency = kwargs.get('lastFrequency', 0)
        self.verified = kwargs.get('verified', False)
        self.latitude = kwargs.get('latitude', 0)
        self.longitude = kwargs.get('longitude', 0)
        self.altitude = kwargs.get('altitude', 0)
        self.misc_attribs = kwargs.get('misc_attribs', {})
        self.probe_response_data = kwargs.get('probe_response_data', {})
        self.beacon_data = kwargs.get('beacon_data', {})
        self.created = kwargs.get('created', mydatetime.utcnow())

    def __getitem__(self, item):
        return getattr(self, item)


@architect.install('partition', type='range', subtype='date', constraint='month', column='created', orm='sqlalchemy', db=app.config['SQLALCHEMY_DATABASE_URI'])
class RawClient(talosdb.Model, UrlIdMixin):
    """
    """
    __tablename__ = 'raw_clients'
    id = talosdb.Column(talosdb.Integer(), primary_key=True)
    client_id = talosdb.Column(talosdb.Integer(), talosdb.ForeignKey('clients.id', ondelete='SET NULL'))
    accesspoint_id = talosdb.Column(talosdb.Integer(), talosdb.ForeignKey('accesspoints.id', ondelete='SET NULL'))
    wrat_id = talosdb.Column(talosdb.Integer, talosdb.ForeignKey('wrats.id', ondelete='SET NULL'))
    __table_args__ = (talosdb.Index('ix_raw_clients_created_clientid', 'created', 'client_id'),)

    channel = talosdb.Column(talosdb.Float, server_default='0.0')
    signal_dbm = talosdb.Column(talosdb.Integer, server_default='0')
    noise_dbm = talosdb.Column(talosdb.Integer, server_default='0')
    signal_rssi = talosdb.Column(talosdb.Integer, server_default='0')
    noise_rssi = talosdb.Column(talosdb.Integer, server_default='0')
    probes = talosdb.Column(talosdb.ARRAY(talosdb.Unicode, dimensions=1))
    latitude = talosdb.Column(talosdb.Float)
    longitude = talosdb.Column(talosdb.Float)
    altitude = talosdb.Column(talosdb.Float)
    misc_attribs = talosdb.Column(MutableDict.as_mutable(JSONB))

    # Timestamps
    created = talosdb.Column(talosdb.DateTime, server_default=text("CURRENT_TIMESTAMP"))

    def __init__(self, **kwargs):
        self.client_id = kwargs.get('client_id')
        self.accesspoint_id = kwargs.get('accesspoint_id')
        self.wrat_id = kwargs.get('wrat_id')
        self.channel = int(kwargs.get('channel', 0))
        self.signal_dbm = kwargs.get('signal_dbm')
        self.noise_dbm = kwargs.get('noise_dbm')
        self.signal_rssi = kwargs.get('signal_rssi')
        self.noise_rssi = kwargs.get('noise_rssi')
        self.probes = kwargs.get('probes', [])
        self.latitude = kwargs.get('latitude', 0)
        self.longitude = kwargs.get('longitude', 0)
        self.altitude = kwargs.get('altitude', 0)
        self.misc_attribs = kwargs.get('misc_attribs', {})
        self.created = kwargs.get('created', mydatetime.utcnow())

    def __getitem__(self, item):
        return getattr(self, item)


class WPAHandshake(talosdb.Model, UrlIdMixin):
    """
    WPA/WPA2 handshakes in hccap format
    """
    __tablename__ = 'wpa_handshakes'
    id = talosdb.Column(talosdb.Integer(), primary_key=True)
    customer_id = talosdb.Column(talosdb.Integer, talosdb.ForeignKey('customers.id', ondelete='SET NULL'))
    accesspoint_id = talosdb.Column(talosdb.Integer(), talosdb.ForeignKey('accesspoints.id', ondelete='SET NULL'))

    hccap = talosdb.Column(talosdb.UnicodeText)
    passphrase = talosdb.Column(talosdb.Unicode(length=model_constants['MAX_WPA_PASSPHRASE']), server_default=u'')
    recovery_log = talosdb.Column(talosdb.UnicodeText)

    # hccap details
    hccap_mac_ap = talosdb.Column(talosdb.Unicode(length=model_constants['BSSID_LEN']))
    hccap_mac_station = talosdb.Column(talosdb.Unicode(length=model_constants['MAC_ADDRESS_LEN']))
    hccap_essid = talosdb.Column(talosdb.Unicode)

    # Timestamps
    last_recovery_attempt = talosdb.Column(talosdb.DateTime)
    recovered = talosdb.Column(talosdb.DateTime)
    created = talosdb.Column(talosdb.DateTime, server_default=text("CURRENT_TIMESTAMP"))
    updated = talosdb.Column(talosdb.DateTime, onupdate=mydatetime.utcnow)

    __table_args__ = (
        talosdb.Index('ix_wpahandshake_accesspoint_hccap', 'accesspoint_id', 'hccap', unique=True),
        talosdb.Index('ix_wpahandshake_created', 'created', postgresql_ops={'created': 'DESC'}),
    )

    def __init__(self, **kwargs):
        self.customer_id = kwargs.get('customer_id')
        self.accesspoint_id = kwargs.get('accesspoint_id')
        self.hccap = kwargs.get('hccap')
        self.passphrase = kwargs.get('passphrase')
        self.recovered = kwargs.get('recovered', False)
        self.last_recovery_attempt = kwargs.get('last_recovery_attempt')
        self.recovered = kwargs.get('recovered')

        # hccap-specific details to save in the db record, add colons and upper case to BSSID/MACs
        self.hccap_essid = kwargs.get('hccap_essid', '')
        self.hccap_mac_ap = self.hccap_mac_to_str(kwargs.get('hccap_mac_ap', ''))
        self.hccap_mac_station = self.hccap_mac_to_str(kwargs.get('hccap_mac_station', ''))

    @staticmethod
    def hccap_mac_to_str(hccap_address):
        """Converts an HCCAP byte string for mac_ap/mac_station to an uppercase BSSID/MAC"""
        if not isinstance(hccap_address, bytes):
            app.logger.error(f'HCCAP address not bytes: {hccap_address}')
            return hccap_address
        try:
            hccap_address = binascii.hexlify(hccap_address)
            return b':'.join([hccap_address[i:i + 2] for i in range(0, len(hccap_address), 2)]).decode('utf-8').upper()
        except ValueError as err:
            app.logger.error(f'Invalid hccap address: {hccap_address}: {err}')
            return None


class X509Certs(talosdb.Model, UrlIdMixin):
    """
    Collection of 802.1x EAP-TLS X.509 Certificates
    """
    __tablename__ = 'x509_certs'
    id = talosdb.Column(talosdb.Integer(), primary_key=True)
    customer_id = talosdb.Column(talosdb.Integer, talosdb.ForeignKey('customers.id', ondelete='SET NULL'))
    client_id = talosdb.Column(talosdb.Integer(), talosdb.ForeignKey('clients.id', ondelete='SET NULL'))
    accesspoint_id = talosdb.Column(talosdb.Integer(), talosdb.ForeignKey('accesspoints.id', ondelete='SET NULL'))

    certificate = talosdb.Column(talosdb.UnicodeText)

    serial = talosdb.Column(talosdb.Unicode, server_default=u'', index=True)
    issuer = talosdb.Column(talosdb.Unicode, server_default=u'', index=True)
    subject = talosdb.Column(talosdb.Unicode, server_default=u'')
    public_key = talosdb.Column(talosdb.Unicode, server_default=u'', index=True)
    public_key_bits = talosdb.Column(talosdb.Integer)

    signature_algorithm = talosdb.Column(talosdb.Unicode, server_default=u'')
    signature_value = talosdb.Column(talosdb.Unicode, server_default=u'')
    not_before = talosdb.Column(talosdb.DateTime)
    not_after = talosdb.Column(talosdb.DateTime)

    # Timestamps
    created = talosdb.Column(talosdb.DateTime, server_default=text("CURRENT_TIMESTAMP"))
    updated = talosdb.Column(talosdb.DateTime, onupdate=mydatetime.utcnow)

    __table_args__ = (talosdb.Index('ix_x509certs_accesspoint_signature_value', 'accesspoint_id', 'signature_value', unique=True),)

    def __init__(self, **kwargs):
        self.customer_id = kwargs.get('customer_id')
        self.client_id = kwargs.get('client_id')
        self.accesspoint_id = kwargs.get('accesspoint_id')
        self.certificate = kwargs.get('certificate')
        self.serial = kwargs.get('serial')
        self.issuer = kwargs.get('issuer')
        self.subject = kwargs.get('subject')
        self.public_key = kwargs.get('public_key')
        self.public_key_bits = kwargs.get('public_key_bits')
        self.signature_algorithm = kwargs.get('signature_algorithm')
        self.signature_value = kwargs.get('signature_value')
        self.not_before = kwargs.get('not_before')
        self.not_after = kwargs.get('not_after')

    def details(self):
        """Return the certificate and its decoded data"""
        return {
            'certificate': self.certificate,
            'serial': self.serial,
            'issuer': self.issuer,
            'subject': self.subject,
            'public_key': self.public_key,
            'public_key_bits': self.public_key_bits,
            'signature_algorithm': self.signature_algorithm,
            'signature_value': self.signature_value,
            'valid_not_before': self.not_before,
            'valid_not_after': self.not_after,
            'capture_date': self.created.isoformat()
        }
