"""
Pentest Toolbox - Configuration
"""
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-prod'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'pentest.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Tool paths (for local execution fallback)
    NMAP_PATH = os.environ.get('NMAP_PATH') or 'nmap'
    NIKTO_PATH = os.environ.get('NIKTO_PATH') or 'nikto'
    
    # Docker / Exegol settings
    USE_DOCKER = os.environ.get('USE_DOCKER', 'true').lower() == 'true'
    EXEGOL_IMAGE = os.environ.get('EXEGOL_IMAGE') or 'nwodtuhs/exegol-full:latest'
    CONTAINER_TIMEOUT = int(os.environ.get('CONTAINER_TIMEOUT', 600))  # 10 min max
    CONTAINER_MEMORY_LIMIT = os.environ.get('CONTAINER_MEMORY_LIMIT') or '2g'
    RESULTS_VOLUME = os.path.join(BASE_DIR, 'scan_results')
