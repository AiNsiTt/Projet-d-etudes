"""
Pentest Toolbox V1 - Flask Application
"""
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from config import Config
from models import db, Scan, Vulnerability
from scanner import Scanner

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

# Initialize scanner
scanner = Scanner(app)

# Create tables on first request
with app.app_context():
    db.create_all()

# =============================================================================
# TEMPLATE ROUTES
# =============================================================================

@app.route('/')
@app.route('/dashboard')
def dashboard():
    """Dashboard with KPIs and recent scans"""
    scans = Scan.query.order_by(Scan.created_at.desc()).limit(10).all()
    
    # Calculate stats
    total_scans = Scan.query.count()
    total_vulns = Vulnerability.query.count()
    completed = Scan.query.filter_by(status='completed').count()
    
    # Severity counts
    severity_counts = {
        'critical': Vulnerability.query.filter_by(severity='critical').count(),
        'high': Vulnerability.query.filter_by(severity='high').count(),
        'medium': Vulnerability.query.filter_by(severity='medium').count(),
        'low': Vulnerability.query.filter_by(severity='low').count(),
    }
    
    return render_template('dashboard.html', 
        scans=scans,
        total_scans=total_scans,
        total_vulns=total_vulns,
        completed_scans=completed,
        severity=severity_counts
    )

@app.route('/new-scan')
def new_scan():
    """Scan configuration form"""
    return render_template('new_scan.html')

@app.route('/console/<int:scan_id>')
def console(scan_id):
    """Live console view for a scan"""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        flash('Scan not found', 'error')
        return redirect(url_for('dashboard'))
    return render_template('console.html', scan=scan)

@app.route('/results/<int:scan_id>')
def results(scan_id):
    """Results view for a completed scan"""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        flash('Scan not found', 'error')
        return redirect(url_for('dashboard'))
    
    vulns = Vulnerability.query.filter_by(scan_id=scan_id).order_by(
        db.case(
            (Vulnerability.severity == 'critical', 1),
            (Vulnerability.severity == 'high', 2),
            (Vulnerability.severity == 'medium', 3),
            (Vulnerability.severity == 'low', 4),
            else_=5
        )
    ).all()
    
    return render_template('results.html', scan=scan, vulnerabilities=vulns)

# =============================================================================
# API ROUTES
# =============================================================================

@app.route('/api/scan/create', methods=['POST'])
def create_scan():
    """Create and start a new scan"""
    target = request.form.get('target', '').strip()
    tools = request.form.getlist('tools')
    
    if not target:
        flash('Please enter a target', 'error')
        return redirect(url_for('new_scan'))
    
    if not tools:
        tools = ['nmap']  # Default to nmap
    
    # Create scan record
    scan = Scan(
        target=target,
        tools=','.join(tools),
        status='pending'
    )
    db.session.add(scan)
    db.session.commit()
    
    # Start scan in background
    scanner.run_scan_async(scan.id)
    
    flash(f'Scan #{scan.id} started!', 'success')
    return redirect(url_for('console', scan_id=scan.id))

@app.route('/api/scan/<int:scan_id>/status')
def scan_status(scan_id):
    """API endpoint for polling scan status"""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan.to_dict())

@app.route('/api/scan/<int:scan_id>/stop', methods=['POST'])
def stop_scan(scan_id):
    """Stop a running scan"""
    scan = db.session.get(Scan, scan_id)
    if scan and scan.status == 'running':
        scan.status = 'failed'
        scan.output += '\n[!] Scan stopped by user\n'
        db.session.commit()
    return jsonify({'status': 'stopped'})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
