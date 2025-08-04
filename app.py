from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for, send_file
from document_analyzer import AIAgentAnalyzer
from auth import validate_user
import os
import pandas as pd
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

app = Flask(__name__)
app.secret_key = 'doc_analyzer_secret_key'

LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>AI Agent Analyzer - Login</title>
    <style>
        body { font-family: Arial; max-width: 400px; margin: 100px auto; padding: 20px; }
        input { width: 100%; padding: 10px; margin: 10px 0; }
        button { width: 100%; padding: 12px; background: #007cba; color: white; border: none; }
        .error { color: red; margin: 10px 0; }
    </style>
</head>
<body>
    <h2>AI Agent Analyzer</h2>
    <form method="POST">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    <div style="margin-top: 20px; font-size: 12px; color: #666;">
        Demo credentials: admin / password
    </div>
</body>
</html>
'''

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>AI Agent Analyzer</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1200px; margin: 20px auto; padding: 20px; background: #f5f5f5; }
        .header { display: flex; justify-content: space-between; align-items: center; background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .dashboard { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px; }
        .dashboard-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .dashboard-single { grid-column: 1 / -1; }
        input[type="text"] { width: 400px; padding: 10px; border: 1px solid #ddd; border-radius: 4px; margin: 10px 0; }
        button { padding: 12px 20px; border: none; border-radius: 4px; cursor: pointer; margin: 5px; font-weight: bold; }
        .primary { background: #007cba; color: white; }
        .danger { background: #dc3545; color: white; }
        .info { background: #17a2b8; color: white; }
        .success { background: #28a745; color: white; }
        button:disabled { background: #ccc; cursor: not-allowed; }
        .browse { background: #6c757d; color: white; }
        pre { background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; border: 1px solid #e9ecef; }
        .spinner { animation: spin 1s linear infinite; display: inline-block; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .risk-summary { margin-bottom: 20px; }
        .risk-item { background: #f8f9fa; border-left: 4px solid #007cba; padding: 10px; margin: 10px 0; border-radius: 4px; }
        .risk-high { border-left-color: #dc3545; }
        .risk-medium { border-left-color: #ffc107; }
        .risk-low { border-left-color: #28a745; }
        .risk-header { font-weight: bold; color: #333; margin-bottom: 5px; }
        .risk-context { color: #666; font-size: 0.9em; }
        .mitigation-item { background: #e8f5e8; border-left: 4px solid #28a745; padding: 10px; margin: 10px 0; border-radius: 4px; }
        .mitigation-header { font-weight: bold; color: #155724; margin-bottom: 5px; }
        .mitigation-text { color: #155724; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }
        .stat-card { text-align: center; padding: 15px; background: #f8f9fa; border-radius: 8px; }
        .stat-number { font-size: 2em; font-weight: bold; color: #007cba; }
        .stat-label { color: #666; font-size: 0.9em; }
        .tabs { display: flex; border-bottom: 2px solid #eee; margin-bottom: 20px; }
        .tab { padding: 10px 20px; cursor: pointer; border-bottom: 2px solid transparent; }
        .tab.active { border-bottom-color: #007cba; color: #007cba; font-weight: bold; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .severity-high { color: #dc3545; font-weight: bold; }
        .severity-medium { color: #ffc107; font-weight: bold; }
        .severity-low { color: #28a745; font-weight: bold; }
        .analyze-form { max-width: 600px; margin: 0 auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>AI Agent Analyzer</h1>
        <a href="/logout"><button class="danger">Logout</button></a>
    </div>
    
    <div class="container">
        <form method="POST" action="/analyze">
            <label>Repository Path:</label><br>
            <input type="text" name="path" id="folderPath" placeholder="Enter folder path" value="sample_documents" style="width:400px;">
            <input type="file" id="folderSelect" webkitdirectory multiple style="display:none;">
            <button type="button" class="browse" onclick="document.getElementById('folderSelect').click()">Source</button><br><br>
            <div id="progressContainer" style="display:none; margin:10px 0; text-align:center;">
                <div class="spinner" style="display:inline-block; width:20px; height:20px; border:3px solid #f3f3f3; border-top:3px solid #007cba; border-radius:50%; animation:spin 1s linear infinite;"></div>
                <span style="margin-left:10px; color:#007cba;">Uploading folder...</span>
            </div>
            <button type="submit" class="primary">Analyze</button>
            <button type="button" onclick="downloadExcel()" class="danger" id="riskBtn" style="display:none;" disabled>Get Risk Report</button>
            <button type="button" onclick="downloadMitigation()" class="info" id="mitigationBtn" style="display:none;" disabled>Mitigation Plan</button>
        </form>
    </div>
    <script>
        document.getElementById('folderSelect').addEventListener('change', function(e) {
            if (e.target.files.length > 0) {
                document.getElementById('progressContainer').style.display = 'block';
                const file = e.target.files[0];
                const folderName = file.webkitRelativePath.split('/')[0];
                setTimeout(function() {
                    document.getElementById('folderPath').value = folderName;
                    document.getElementById('progressContainer').style.display = 'none';
                }, 1500);
            }
        });
        function downloadExcel() {}
        function downloadMitigation() {}
    </script>
    
    <div style="margin-top:10px; font-size:12px; color:#666;">
        Examples: C:\\Users\\Documents, ./project-docs, /home/user/files
    </div>
    
    {% if dashboard_data %}
    <div class="dashboard">
        <!-- Risk Summary Stats -->
        <div class="dashboard-card dashboard-single">
            <h2>Risk Analysis Dashboard</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{{ dashboard_data.total_documents }}</div>
                    <div class="stat-label">Documents Analyzed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ dashboard_data.total_risks }}</div>
                    <div class="stat-label">Total Risks Found</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ dashboard_data.high_risks }}</div>
                    <div class="stat-label">High Severity</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ dashboard_data.medium_risks }}</div>
                    <div class="stat-label">Medium Severity</div>
                </div>
            </div>
        </div>
        
        <!-- Tabbed Interface -->
        <div class="dashboard-card dashboard-single">
            <div class="tabs">
                <div class="tab active" id="summaryTab" onclick="switchTab('summary')">Risk Summary</div>
                <div class="tab" id="mitigationTab" onclick="switchTab('mitigation')">Mitigation Plan</div>
                <div class="tab" id="detailsTab" onclick="switchTab('details')">Analysis Details</div>
            </div>
            
            <!-- Risk Summary Tab -->
            <div class="tab-content active" id="summaryContent">
                <h3>Risk Items by Severity</h3>
                {% for risk in dashboard_data.all_risks %}
                <div class="risk-item risk-{{ risk.severity.lower() }}">
                    <div class="risk-header">
                        <span class="severity-{{ risk.severity.lower() }}">[{{ risk.severity }}]</span>
                        <b>{{ risk.keyword }}</b> in <b>{{ risk.file }}</b> (Line {{ risk.line }})
                    </div>
                    <div class="risk-context"><b>Description:</b> {{ risk.context }}</div>
                    <div class="risk-context"><b>Severity:</b> {{ risk.severity }}</div>
                    <div class="risk-context"><b>Detected At:</b> {{ risk.file }}:{{ risk.line }}</div>
                </div>
                {% endfor %}
            </div>
            
            <!-- Mitigation Plan Tab -->
            <div class="tab-content" id="mitigationContent">
                <h3>Recommended Mitigation Strategies</h3>
                {% if dashboard_data.all_risks and dashboard_data.mitigations %}
                {% for risk in dashboard_data.all_risks %}
                <div class="mitigation-item">
                    <div class="mitigation-header">
                        <b>Risk:</b> {{ risk.keyword }} in <b>{{ risk.file }}</b> (Line {{ risk.line }})
                    </div>
                    <div class="mitigation-text">
                        <b>Severity:</b> {{ risk.severity }}<br>
                        <b>Description:</b> {{ risk.context }}<br>
                        <b>Mitigation:</b> {{ dashboard_data.mitigations[risk.keyword] }}<br>
                        <b>Suggestions:</b>
                        <ul>
                        {% set suggestions = dashboard_data.suggestions.get(risk.keyword, []) %}
                        {% for suggestion in suggestions %}
                            <li>{{ suggestion }}</li>
                        {% endfor %}
                        </ul>
                    </div>
                </div>
                {% endfor %}
                {% else %}
                <div style="color:#888; font-size:1em; margin:20px 0;">No mitigation data available. Please run analysis.</div>
                {% endif %}
            </div>
            <!-- Analysis Details Tab -->
            <div class="tab-content" id="detailsContent">
                <h3>Complete Analysis Report</h3>
                {% if dashboard_data.full_report %}
                <pre>{{ dashboard_data.full_report }}</pre>
                {% else %}
                <div style="color:#888; font-size:1em; margin:20px 0;">No analysis details available. Please run analysis.</div>
                {% endif %}
            </div>
        </div>
    </div>
    
    <script>
        // Enable buttons after analysis
        document.getElementById('riskBtn').disabled = false;
        document.getElementById('mitigationBtn').disabled = false;
    </script>
    {% endif %}
</body>
</html>
'''

def generate_mitigation_suggestions(keyword):
    """Return actionable suggestions for each risk keyword."""
    suggestions = {
        'password': [
            'Deploy enterprise password manager (LastPass, 1Password, Bitwarden)',
            'Implement passwordless authentication (FIDO2, Windows Hello)',
            'Monitor dark web for credential exposure',
            'Establish password policy enforcement (complexity, length, history)',
            'Deploy privileged access management (PAM) solution'
        ],
        'security': [
            'Implement Security Information and Event Management (SIEM)',
            'Deploy Security Orchestration, Automation and Response (SOAR)',
            'Establish Security Operations Center (SOC) with 24/7 monitoring',
            'Conduct regular penetration testing and red team exercises',
            'Implement security awareness training with phishing simulations'
        ],
        'vulnerability': [
            'Deploy continuous vulnerability management platform (Qualys, Rapid7)',
            'Implement automated patch management system',
            'Establish vulnerability disclosure and bug bounty program',
            'Integrate security testing into CI/CD pipeline (DevSecOps)',
            'Conduct regular security code reviews and static analysis'
        ],
        'risk': [
            'Document all identified risks.',
            'Assign risk owners for mitigation.',
            'Review risk register quarterly.'
        ],
        'critical': [
            'Implement high availability and disaster recovery solutions',
            'Establish incident command system with clear escalation paths',
            'Deploy real-time monitoring and alerting for critical systems',
            'Conduct regular business continuity and disaster recovery testing',
            'Maintain updated emergency contact lists and communication plans'
        ],
        'unauthorized': [
            'Audit user permissions regularly.',
            'Implement access request workflows.',
            'Monitor for suspicious access attempts.'
        ],
        'threat': [
            'Subscribe to threat intelligence feeds.',
            'Simulate threat scenarios for readiness.',
            'Review incident response playbooks.'
        ],
        'compliance': [
            'Assign compliance champions.',
            'Automate compliance reporting.',
            'Stay updated on regulatory changes.'
        ],
        'warning': [
            'Set up alert thresholds.',
            'Review warning logs weekly.',
            'Investigate recurring warnings.'
        ],
        'breach': [
            'Practice breach response drills.',
            'Maintain up-to-date contact lists.',
            'Review breach notification procedures.'
        ],
        'failure': [
            'Test backup restoration.',
            'Document failure scenarios.',
            'Monitor system health metrics.'
        ],
        'error': [
            'Log all errors centrally.',
            'Review error logs for patterns.',
            'Automate error notifications.'
        ],
        'urgent': [
            'Define urgent escalation paths.',
            'Allocate resources for urgent issues.',
            'Review urgent issue history.'
        ],
        'danger': [
            'Conduct safety training.',
            'Review emergency exits and protocols.',
            'Test alarm systems.'
        ],
        'issue': [
            'Track issues in a central system.',
            'Assign issue owners.',
            'Review unresolved issues monthly.'
        ],
        'problem': [
            'Document problem statements clearly.',
            'Review problem management KPIs.',
            'Share lessons learned from problems.'
        ],
        'concern': [
            'Hold regular stakeholder meetings.',
            'Document concerns and resolutions.',
            'Monitor for new concerns.'
        ],
        'audit': [
            'Schedule internal audits.',
            'Prepare audit checklists.',
            'Review audit findings with teams.'
        ],
        'violation': [
            'Train staff on policy violations.',
            'Document all violations.',
            'Review violation trends.'
        ],
        'malicious': [
            'Deploy next-generation antivirus with behavioral analysis',
            'Implement threat intelligence feeds and indicators of compromise (IOCs)',
            'Establish security information sharing with industry partners',
            'Deploy deception technology and honeypots',
            'Implement user and entity behavior analytics (UEBA)'
        ],
        'attack': [
            'Implement attack surface management and continuous monitoring',
            'Deploy intrusion detection and prevention systems (IDS/IPS)',
            'Conduct regular red team exercises and adversary simulations',
            'Implement threat hunting and proactive threat detection',
            'Establish cyber threat intelligence program with external feeds'
        ]
    }
    return suggestions.get(keyword.lower(), ['Review and document next steps.', 'Consult with subject matter experts.', 'Monitor for recurrence.'])

@app.route('/')
def home():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    return render_template_string(HTML_TEMPLATE, dashboard_data=None)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Validate credentials
        if validate_user(username, password):
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return render_template_string(LOGIN_TEMPLATE, error='Invalid credentials')
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    path = request.form.get('path', '').strip()
    
    if not path:
        return render_template_string(HTML_TEMPLATE, dashboard_data=None)
    
    # Handle relative paths from current working directory
    if not os.path.isabs(path):
        path = os.path.join(os.getcwd(), path)
    path = os.path.abspath(path)
    
    if not os.path.exists(path):
        # If path doesn't exist, try to use sample_documents as fallback
        fallback_path = os.path.join(os.getcwd(), 'sample_documents')
        if os.path.exists(fallback_path):
            path = fallback_path
        else:
            # Pass error and empty dashboard keys to avoid template error
            dashboard_data = {
                'error': f"Path '{path}' does not exist. Please use 'sample_documents' or upload files.",
                'total_documents': 0,
                'total_risks': 0,
                'high_risks': 0,
                'medium_risks': 0,
                'low_risks': 0,
                'all_risks': [],
                'mitigations': {},
                'full_report': '',
                'repository_path': ''
            }
            return render_template_string(HTML_TEMPLATE, dashboard_data=dashboard_data)
    
    if not os.path.isdir(path):
        dashboard_data = {
            'error': f"'{path}' is not a directory",
            'total_documents': 0,
            'total_risks': 0,
            'high_risks': 0,
            'medium_risks': 0,
            'low_risks': 0,
            'all_risks': [],
            'mitigations': {},
            'full_report': '',
            'repository_path': ''
        }
        return render_template_string(HTML_TEMPLATE, dashboard_data=dashboard_data)
    
    try:
        agent = AIAgentAnalyzer(path)
        results = agent.analyze_repository()
        report = agent.generate_report(results)
        
        # Store results in session for Excel download
        session['last_results'] = results
        
        # Prepare dashboard data
        risk_data = results.get('risk_items', {})
        all_risks = risk_data.get('all_risks', [])
        
        # Generate mitigation strategies and suggestions
        mitigations = {}
        suggestions = {}
        for risk in all_risks:
            keyword = risk['keyword']
            if keyword not in mitigations:
                mitigations[keyword] = generate_mitigation(keyword)
                suggestions[keyword] = generate_mitigation_suggestions(keyword)
        dashboard_data = {
            'total_documents': results['total_documents'],
            'total_risks': len(all_risks),
            'high_risks': len([r for r in all_risks if r['severity'] == 'HIGH']),
            'medium_risks': len([r for r in all_risks if r['severity'] == 'MEDIUM']),
            'low_risks': len([r for r in all_risks if r['severity'] == 'LOW']),
            'all_risks': all_risks,
            'mitigations': mitigations,
            'suggestions': suggestions,
            'full_report': report,
            'repository_path': results['repository_path']
        }
        
        return render_template_string(HTML_TEMPLATE, dashboard_data=dashboard_data)
    except Exception as e:
        dashboard_data = {
            'error': f"Error analyzing path: {str(e)}",
            'total_documents': 0,
            'total_risks': 0,
            'high_risks': 0,
            'medium_risks': 0,
            'low_risks': 0,
            'all_risks': [],
            'mitigations': {},
            'full_report': '',
            'repository_path': ''
        }
        return render_template_string(HTML_TEMPLATE, dashboard_data=dashboard_data)

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    # API authentication check
    auth_header = request.headers.get('Authorization')
    if not auth_header or auth_header != 'Bearer admin:password':
        return jsonify({'error': 'Authentication required'}), 401
    data = request.json
    path = data.get('path', '').strip()
    
    if not path:
        return jsonify({'error': 'Path is required'}), 400
    
    # Handle relative paths from current working directory
    if not os.path.isabs(path):
        path = os.path.join(os.getcwd(), path)
    path = os.path.abspath(path)
    
    if not os.path.exists(path):
        # Try fallback to sample_documents
        fallback_path = os.path.join(os.getcwd(), 'sample_documents')
        if os.path.exists(fallback_path):
            path = fallback_path
        else:
            return jsonify({'error': f'Path does not exist: {path}. Use sample_documents.'}), 400
    
    if not os.path.isdir(path):
        return jsonify({'error': f'Path is not a directory: {path}'}), 400
    
    try:
        agent = AIAgentAnalyzer(path)
        results = agent.analyze_repository()
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/mitigation', methods=['POST'])
def api_mitigation():
    """REST API endpoint to get mitigation plan"""
    # API authentication check
    auth_header = request.headers.get('Authorization')
    if not auth_header or auth_header != 'Bearer admin:password':
        return jsonify({'error': 'Authentication required'}), 401
    
    data = request.json
    path = data.get('path', '').strip()
    
    if not path:
        return jsonify({'error': 'Path is required'}), 400
    
    # Handle relative paths from current working directory
    if not os.path.isabs(path):
        path = os.path.join(os.getcwd(), path)
    path = os.path.abspath(path)
    
    if not os.path.exists(path):
        # Try fallback to sample_documents
        fallback_path = os.path.join(os.getcwd(), 'sample_documents')
        if os.path.exists(fallback_path):
            path = fallback_path
        else:
            return jsonify({'error': f'Path does not exist: {path}. Use sample_documents.'}), 400
    
    if not os.path.isdir(path):
        return jsonify({'error': f'Path is not a directory: {path}'}), 400
    
    try:
        agent = AIAgentAnalyzer(path)
        results = agent.analyze_repository()
        risks = results['risk_items']['all_risks']
        
        # Generate mitigation plan
        mitigation_plan = []
        for risk in risks:
            mitigation = generate_mitigation(risk['keyword'])
            mitigation_plan.append({
                'risk': {
                    'file': risk['file'],
                    'line': risk['line'],
                    'keyword': risk['keyword'],
                    'context': risk['context'],
                    'severity': risk['severity']
                },
                'mitigation': mitigation
            })
        
        return jsonify({
            'repository_path': path,
            'total_risks': len(risks),
            'mitigation_plan': mitigation_plan
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download-excel')
def download_excel():
    if 'logged_in' not in session or 'last_results' not in session:
        return jsonify({'error': 'No analysis data available'}), 400
    
    try:
        results = session['last_results']
        risks = results['risk_items']['all_risks']
        
        # Create simple CSV instead of Excel for serverless
        import io
        output = io.StringIO()
        output.write('File,Line,Keyword,Context,Severity\n')
        
        for risk in risks:
            output.write(f"{risk['file']},{risk['line']},{risk['keyword']},\"{risk['context']}\",{risk['severity']}\n")
        
        # Create response
        from flask import Response
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=risk_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download-mitigation')
def download_mitigation():
    if 'logged_in' not in session or 'last_results' not in session:
        return jsonify({'error': 'No analysis data available'}), 400
    
    try:
        results = session['last_results']
        risks = results['risk_items']['all_risks']
        
        # Create text-based mitigation plan
        import io
        output = io.StringIO()
        output.write('RISK MITIGATION PLAN\n')
        output.write('=' * 50 + '\n\n')
        output.write(f'Repository: {results["repository_path"]}\n\n')
        
        for risk in risks:
            output.write(f'RISK: {risk["keyword"]} in {risk["file"]} (Line {risk["line"]})\n')
            output.write(f'Context: {risk["context"]}\n')
            mitigation = generate_mitigation(risk['keyword'])
            output.write(f'Mitigation: {mitigation}\n')
            output.write('-' * 50 + '\n\n')
        
        # Create response
        from flask import Response
        return Response(
            output.getvalue(),
            mimetype='text/plain',
            headers={'Content-Disposition': f'attachment; filename=mitigation_plan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'}
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def generate_mitigation(keyword):
    """Generate detailed mitigation strategies for each risk keyword"""
    mitigations = {
        'password': 'IMMEDIATE: Change default passwords, enforce 12+ character complexity. SHORT-TERM: Deploy MFA, password managers. LONG-TERM: Implement zero-trust authentication, biometric controls.',
        'security': 'IMMEDIATE: Conduct security assessment, patch critical vulnerabilities. SHORT-TERM: Deploy SIEM, establish SOC. LONG-TERM: Implement security framework (ISO 27001), continuous monitoring.',
        'vulnerability': 'IMMEDIATE: Apply critical patches, isolate affected systems. SHORT-TERM: Deploy vulnerability scanner, establish patch management. LONG-TERM: Implement DevSecOps, automated testing.',
        'risk': 'IMMEDIATE: Document and assess risk impact. SHORT-TERM: Implement risk controls, establish monitoring. LONG-TERM: Deploy risk management framework (NIST, ISO 31000), regular reviews.',
        'critical': 'IMMEDIATE: Activate emergency response, contain impact. SHORT-TERM: Implement business continuity plan, establish 24/7 monitoring. LONG-TERM: Build resilient architecture, disaster recovery.',
        'unauthorized': 'IMMEDIATE: Revoke unauthorized access, audit permissions. SHORT-TERM: Implement RBAC, deploy PAM solution. LONG-TERM: Zero-trust architecture, continuous access validation.',
        'threat': 'IMMEDIATE: Activate threat response, isolate systems. SHORT-TERM: Deploy EDR/XDR, threat intelligence. LONG-TERM: Establish threat hunting program, AI-powered detection.',
        'compliance': 'IMMEDIATE: Identify compliance gaps, implement quick fixes. SHORT-TERM: Deploy compliance monitoring, staff training. LONG-TERM: Automated compliance reporting, continuous auditing.',
        'warning': 'IMMEDIATE: Investigate warning source, implement temporary controls. SHORT-TERM: Establish alerting thresholds, response procedures. LONG-TERM: Predictive analytics, automated remediation.',
        'breach': 'IMMEDIATE: Contain breach, preserve evidence, notify authorities. SHORT-TERM: Forensic analysis, stakeholder communication. LONG-TERM: Strengthen defenses, incident response improvement.',
        'failure': 'IMMEDIATE: Restore service, implement workaround. SHORT-TERM: Root cause analysis, backup validation. LONG-TERM: Redundant systems, chaos engineering, resilience testing.',
        'error': 'IMMEDIATE: Fix critical errors, implement logging. SHORT-TERM: Error monitoring, automated alerts. LONG-TERM: Predictive error detection, self-healing systems.',
        'deprecated': 'IMMEDIATE: Assess security risks, implement compensating controls. SHORT-TERM: Plan migration, security hardening. LONG-TERM: Complete modernization, legacy system replacement.',
        'legacy': 'IMMEDIATE: Security assessment, network isolation. SHORT-TERM: Implement monitoring, access controls. LONG-TERM: System modernization, cloud migration strategy.',
        'insecure': 'IMMEDIATE: Apply security hardening, encrypt data. SHORT-TERM: Security configuration management, monitoring. LONG-TERM: Secure-by-design architecture, zero-trust implementation.',
        'exposed': 'IMMEDIATE: Remove exposure, implement access controls. SHORT-TERM: Network segmentation, monitoring. LONG-TERM: Attack surface management, continuous exposure assessment.',
        'injection': 'IMMEDIATE: Input validation, parameterized queries. SHORT-TERM: Deploy WAF, code review. LONG-TERM: Secure coding practices, automated security testing.',
        'overflow': 'IMMEDIATE: Apply patches, implement bounds checking. SHORT-TERM: Code analysis, runtime protection. LONG-TERM: Memory-safe languages, secure development lifecycle.',
        'malicious': 'IMMEDIATE: Isolate systems, malware removal. SHORT-TERM: Deploy anti-malware, behavioral analysis. LONG-TERM: AI-powered threat detection, user behavior analytics.',
        'phishing': 'IMMEDIATE: Block malicious emails, user notification. SHORT-TERM: Email security gateway, user training. LONG-TERM: AI-powered email filtering, security awareness program.',
        'ransomware': 'IMMEDIATE: Isolate systems, activate backup recovery. SHORT-TERM: Endpoint protection, network segmentation. LONG-TERM: Immutable backups, zero-trust architecture.',
        'corruption': 'IMMEDIATE: Restore from backup, data validation. SHORT-TERM: Integrity monitoring, backup testing. LONG-TERM: Immutable storage, blockchain verification.',
        'downtime': 'IMMEDIATE: Restore service, implement failover. SHORT-TERM: High availability setup, monitoring. LONG-TERM: Resilient architecture, chaos engineering.',
        'attack': 'IMMEDIATE: Activate incident response, isolate affected systems. SHORT-TERM: Deploy IDS/IPS, threat hunting. LONG-TERM: Attack surface management, continuous threat intelligence.'
    }
    return mitigations.get(keyword.lower(), 'IMMEDIATE: Assess and document the issue. SHORT-TERM: Implement appropriate controls based on risk level. LONG-TERM: Establish monitoring and continuous improvement processes.')

@app.route('/api/docs')
def api_docs():
    """API Documentation"""
    docs = {
        'title': 'AI Agent Analyzer API',
        'version': '1.0',
        'endpoints': {
            '/api/analyze': {
                'method': 'POST',
                'description': 'Analyze documents and get risk assessment',
                'headers': {'Authorization': 'Bearer admin:password'},
                'body': {'path': 'string - folder path to analyze'},
                'response': 'Complete analysis results with risks and summaries'
            },
            '/api/mitigation': {
                'method': 'POST', 
                'description': 'Get mitigation plan for identified risks',
                'headers': {'Authorization': 'Bearer admin:password'},
                'body': {'path': 'string - folder path to analyze'},
                'response': 'Mitigation strategies for each identified risk'
            }
        },
        'example_request': {
            'url': '/api/mitigation',
            'method': 'POST',
            'headers': {'Authorization': 'Bearer admin:password'},
            'body': {'path': 'sample_documents'}
        }
    }
    return jsonify(docs)

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)