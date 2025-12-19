"""
Pentest Toolbox - Database Models
"""
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Scan(db.Model):
    """Model for pentest scans"""
    __tablename__ = 'scan'
    
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(255), nullable=False)
    tools = db.Column(db.String(255), nullable=False)  # Comma-separated: "nmap,nikto"
    status = db.Column(db.String(50), default='pending')  # pending, running, completed, failed
    progress = db.Column(db.Integer, default=0)  # 0-100
    output = db.Column(db.Text, default='')  # Live logs
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'target': self.target,
            'tools': self.tools.split(','),
            'status': self.status,
            'progress': self.progress,
            'output': self.output,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'vuln_count': len(self.vulnerabilities)
        }


class Vulnerability(db.Model):
    """Model for detected vulnerabilities"""
    __tablename__ = 'vulnerability'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # critical, high, medium, low, info
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    host = db.Column(db.String(255))
    port = db.Column(db.Integer)
    tool = db.Column(db.String(50))  # Which tool found it
    raw_output = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'host': self.host,
            'port': self.port,
            'tool': self.tool
        }
