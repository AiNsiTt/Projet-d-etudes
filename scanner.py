"""
Pentest Toolbox - Scanner Module V1
Handles execution of security tools via Docker/Exegol containers
"""
import subprocess
import threading
import re
from datetime import datetime
from models import db, Scan, Vulnerability
from config import Config

# Try to import Docker manager
try:
    from docker_manager import get_docker_manager
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False


class Scanner:
    """Handles running security scanning tools (via Docker or local)"""
    
    def __init__(self, app):
        self.app = app
        self.use_docker = Config.USE_DOCKER and DOCKER_AVAILABLE
        self.docker_manager = None
        
        if self.use_docker:
            self.docker_manager = get_docker_manager(Config.EXEGOL_IMAGE)
    
    def run_scan_async(self, scan_id):
        """Run scan in background thread"""
        thread = threading.Thread(target=self._execute_scan, args=(scan_id,))
        thread.daemon = True
        thread.start()
    
    def _execute_scan(self, scan_id):
        """Execute the scan with selected tools"""
        with self.app.app_context():
            scan = db.session.get(Scan, scan_id)
            if not scan:
                return
            
            scan.status = 'running'
            scan.output = '[*] Starting scan...\n'
            
            # Check Docker availability
            if self.use_docker and self.docker_manager:
                if self.docker_manager.connect():
                    scan.output += '[+] Docker connected - Using Exegol container\n'
                    if not self.docker_manager.image_exists():
                        scan.output += f'[!] Image {Config.EXEGOL_IMAGE} not found locally\n'
                        scan.output += '[*] Falling back to local execution\n'
                        self.use_docker = False
                else:
                    scan.output += '[!] Docker not available - Using local execution\n'
                    self.use_docker = False
            else:
                scan.output += '[*] Running in local mode\n'
            
            db.session.commit()
            
            tools = scan.tools.split(',')
            total_tools = len(tools)
            
            # Create container if using Docker
            container_id = None
            if self.use_docker and self.docker_manager:
                scan.output += '[*] Creating Exegol container...\n'
                db.session.commit()
                container_id = self.docker_manager.get_or_create_container(scan.id)
                if container_id:
                    scan.output += f'[+] Container ready: {container_id[:12]}\n'
                else:
                    scan.output += '[!] Container creation failed - Using local execution\n'
                    self.use_docker = False
                db.session.commit()
            
            for idx, tool in enumerate(tools):
                tool = tool.strip().lower()
                progress_base = int((idx / total_tools) * 100)
                
                if tool == 'nmap':
                    if self.use_docker and container_id:
                        self._run_nmap_docker(scan, progress_base, 100 // total_tools)
                    else:
                        self._run_nmap_local(scan, progress_base, 100 // total_tools)
                elif tool == 'nikto':
                    if self.use_docker and container_id:
                        self._run_nikto_docker(scan, progress_base, 100 // total_tools)
                    else:
                        self._run_nikto_local(scan, progress_base, 100 // total_tools)
                
                db.session.commit()
            
            # Cleanup container
            if self.use_docker and self.docker_manager and container_id:
                scan.output += '\n[*] Cleaning up container...\n'
                self.docker_manager.cleanup_container(scan.id)
            
            scan.status = 'completed'
            scan.progress = 100
            scan.completed_at = datetime.utcnow()
            scan.output += '\n[+] Scan completed!\n'
            db.session.commit()

    # =========================================================================
    # DOCKER EXECUTION METHODS
    # =========================================================================
    
    def _run_nmap_docker(self, scan, progress_base, progress_share):
        """Execute Nmap scan via Docker container"""
        scan.output += f'\n[*] Running Nmap on {scan.target} (Docker)...\n'
        scan.progress = progress_base + 5
        db.session.commit()
        
        def on_output(line):
            scan.output += line
            db.session.commit()
        
        cmd = f'nmap -sV -sC --top-ports 100 {scan.target}'
        exit_code, output = self.docker_manager.exec_command(
            scan.id, cmd, on_output=on_output, timeout=Config.CONTAINER_TIMEOUT
        )
        
        scan.progress = progress_base + progress_share
        self._parse_nmap_output(scan, output)
    
    def _run_nikto_docker(self, scan, progress_base, progress_share):
        """Execute Nikto scan via Docker container"""
        scan.output += f'\n[*] Running Nikto on {scan.target} (Docker)...\n'
        scan.progress = progress_base + 5
        db.session.commit()
        
        target = scan.target
        if not target.startswith('http'):
            target = f'http://{target}'
        
        def on_output(line):
            scan.output += line
            db.session.commit()
        
        cmd = f'nikto -h {target} -maxtime 120'
        exit_code, output = self.docker_manager.exec_command(
            scan.id, cmd, on_output=on_output, timeout=180
        )
        
        scan.progress = progress_base + progress_share
        self._parse_nikto_output(scan, output)

    # =========================================================================
    # LOCAL EXECUTION METHODS (Fallback)
    # =========================================================================
    
    def _run_nmap_local(self, scan, progress_base, progress_share):
        """Execute Nmap scan locally"""
        scan.output += f'\n[*] Running Nmap on {scan.target} (local)...\n'
        scan.progress = progress_base + 5
        db.session.commit()
        
        try:
            cmd = ['nmap', '-sV', '-sC', '--top-ports', '100', '-oN', '-', scan.target]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )
            
            output = result.stdout + result.stderr
            scan.output += output
            scan.progress = progress_base + progress_share
            self._parse_nmap_output(scan, output)
            
        except subprocess.TimeoutExpired:
            scan.output += '\n[!] Nmap timeout (5 min)\n'
            scan.status = 'failed'
        except FileNotFoundError:
            scan.output += '\n[!] Nmap not found. Please install nmap.\n'
            self._add_mock_nmap_results(scan)
        except Exception as e:
            scan.output += f'\n[!] Nmap error: {str(e)}\n'
    
    def _run_nikto_local(self, scan, progress_base, progress_share):
        """Execute Nikto scan locally"""
        scan.output += f'\n[*] Running Nikto on {scan.target} (local)...\n'
        scan.progress = progress_base + 5
        db.session.commit()
        
        try:
            target = scan.target
            if not target.startswith('http'):
                target = f'http://{target}'
            
            cmd = ['nikto', '-h', target, '-maxtime', '120']
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=180
            )
            
            output = result.stdout + result.stderr
            scan.output += output
            scan.progress = progress_base + progress_share
            self._parse_nikto_output(scan, output)
            
        except subprocess.TimeoutExpired:
            scan.output += '\n[!] Nikto timeout\n'
        except FileNotFoundError:
            scan.output += '\n[!] Nikto not found. Please install nikto.\n'
            self._add_mock_nikto_results(scan)
        except Exception as e:
            scan.output += f'\n[!] Nikto error: {str(e)}\n'

    # =========================================================================
    # PARSING METHODS
    # =========================================================================
    
    def _parse_nmap_output(self, scan, output):
        """Parse Nmap output for vulnerabilities"""
        port_pattern = r'(\d+)/tcp\s+open\s+(\S+)'
        for match in re.finditer(port_pattern, output):
            port, service = match.groups()
            
            risky_services = {
                'ftp': ('medium', 'FTP service detected'),
                'telnet': ('high', 'Telnet (unencrypted) detected'),
                'mysql': ('medium', 'MySQL exposed'),
                'ms-sql': ('medium', 'MSSQL exposed'),
                'vnc': ('high', 'VNC service exposed'),
                'rdp': ('medium', 'RDP service exposed'),
            }
            
            sev, title = risky_services.get(service.lower(), ('info', f'Open port: {service}'))
            
            vuln = Vulnerability(
                scan_id=scan.id, severity=sev, title=title,
                description=f'Port {port}/tcp running {service}',
                host=scan.target, port=int(port), tool='nmap'
            )
            db.session.add(vuln)
    
    def _parse_nikto_output(self, scan, output):
        """Parse Nikto output for vulnerabilities"""
        for line in output.split('\n'):
            if '+ ' in line and ('OSVDB' in line or 'vulnerability' in line.lower()):
                vuln = Vulnerability(
                    scan_id=scan.id, severity='medium',
                    title=line.strip('+ ').split(':')[0][:100],
                    description=line, host=scan.target, tool='nikto'
                )
                db.session.add(vuln)

    # =========================================================================
    # MOCK DATA (for demo when tools not available)
    # =========================================================================
    
    def _add_mock_nmap_results(self, scan):
        """Add mock results when nmap is not installed (for demo)"""
        scan.output += '\n[*] Using mock data for demo...\n'
        mock_vulns = [
            ('info', 'Port 22/tcp Open', 'SSH service running', 22),
            ('info', 'Port 80/tcp Open', 'HTTP server detected', 80),
            ('info', 'Port 443/tcp Open', 'HTTPS server detected', 443),
        ]
        for sev, title, desc, port in mock_vulns:
            vuln = Vulnerability(
                scan_id=scan.id, severity=sev, title=title,
                description=desc, host=scan.target, port=port, tool='nmap'
            )
            db.session.add(vuln)
    
    def _add_mock_nikto_results(self, scan):
        """Add mock results when nikto is not installed (for demo)"""
        scan.output += '\n[*] Using mock data for demo...\n'
        mock_vulns = [
            ('medium', 'Missing X-Frame-Options', 'Clickjacking possible'),
            ('low', 'Server Banner Disclosed', 'Server version visible'),
        ]
        for sev, title, desc in mock_vulns:
            vuln = Vulnerability(
                scan_id=scan.id, severity=sev, title=title,
                description=desc, host=scan.target, tool='nikto'
            )
            db.session.add(vuln)
