from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Target(db.Model):
    __tablename__ = 'targets'
    
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(15), nullable=False)
    hostname = db.Column(db.String(255))
    location = db.Column(db.String(255))
    country = db.Column(db.String(100))
    city = db.Column(db.String(100))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    isp = db.Column(db.String(255))
    location = db.Column(db.String(255))
    asn = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    ports = db.relationship("Port", back_populates="target")

class Port(db.Model):
    __tablename__ = 'ports'
    
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey('targets.id'))
    port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10))
    status = db.Column(db.String(20), default='unknown')
    banner = db.Column(db.String(1024))
    service_name = db.Column(db.String(100))
    version = db.Column(db.String(100))
    
    target = db.relationship("Target", back_populates="ports")
    http_info = db.relationship("HttpInfo", uselist=False, back_populates="port")
    ssl_cert = db.relationship("SSLCert", uselist=False, back_populates="port")
    vulnerabilities = db.relationship("Vulnerability", back_populates="port")

class HttpInfo(db.Model):
    __tablename__ = 'http_info'
    
    id = db.Column(db.Integer, primary_key=True)
    port_id = db.Column(db.Integer, db.ForeignKey('ports.id'))
    title = db.Column(db.String(255))
    server = db.Column(db.String(100))
    tech_stack = db.Column(db.String(255))
    headers = db.Column(db.String(2000))
    directory_list = db.Column(db.Boolean)
    
    port = db.relationship("Port", back_populates="http_info")

class SSLCert(db.Model):
    __tablename__ = 'ssl_certs'
    
    id = db.Column(db.Integer, primary_key=True)
    port_id = db.Column(db.Integer, db.ForeignKey('ports.id'))
    issuer = db.Column(db.String(255))
    subject = db.Column(db.String(255))
    valid_from = db.Column(db.String(50))
    valid_to = db.Column(db.String(50))
    cipher = db.Column(db.String(100))
    protocol_version = db.Column(db.String(20))
    alt_names = db.Column(db.String(500))
    
    port = db.relationship("Port", back_populates="ssl_cert")

class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.Integer, primary_key=True)
    port_id = db.Column(db.Integer, db.ForeignKey('ports.id'))
    cve_id = db.Column(db.String(20))
    description = db.Column(db.String(1000))
    severity = db.Column(db.String(20))
    reference = db.Column(db.String(255))
    
    port = db.relationship("Port", back_populates="vulnerabilities")
