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
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 20px auto; padding: 20px; background: #f5f5f5; }
        .header { display: flex; justify-content: space-between; align-items: center; background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        input[type="text"] { width: 400px; padding: 10px; border: 1px solid #ddd; border-radius: 4px; margin: 10px 0; }
        button { padding: 12px 20px; border: none; border-radius: 4px; cursor: pointer; margin: 5px; font-weight: bold; }
        .primary { background: #007cba; color: white; }
        .danger { background: #dc3545; color: white; }
        .info { background: #17a2b8; color: white; }
        .browse { background: #6c757d; color: white; }
        pre { background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; border: 1px solid #e9ecef; }
        .button-group { margin-top: 15px; }
        .spinner { animation: spin 1s linear infinite; display: inline-block; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
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
            <select id="sourceSelect" onchange="updatePath()" style="padding:10px; margin:10px 0; border:1px solid #ddd; border-radius:4px;">
                <option value="sample_documents">Sample Documents</option>
                <option value="custom">Custom Path</option>
            </select><br>
            <input type="text" name="path" id="folderPath" placeholder="Enter folder path" value="sample_documents" style="width:400px;"><br><br>
            <button type="submit" class="primary">Analyze</button>
            <button type="button" onclick="downloadExcel()" class="danger">Get Risk Report</button>
            <button type="button" onclick="downloadMitigation()" class="info">Mitigation Plan</button>
        </form>
    </div>
    
    <script>
        function updatePath() {
            const select = document.getElementById('sourceSelect');
            const pathInput = document.getElementById('folderPath');
            
            if (select.value === 'sample_documents') {
                pathInput.value = 'sample_documents';
                pathInput.readOnly = true;
            } else {
                pathInput.value = '';
                pathInput.readOnly = false;
                pathInput.placeholder = 'Enter custom folder path';
            }
        }
        
        // Initialize on page load
        updatePath();
        
        function downloadExcel() {
            window.location.href = '/download-excel';
        }
        
        function downloadMitigation() {
            window.location.href = '/download-mitigation';
        }
    </script>
        
        <div style="margin-top:10px; font-size:12px; color:#666;">
            Examples: C:\\Users\\Documents, ./project-docs, /home/user/files
        </div>
        
        {% if results %}
        <div style="margin-top: 20px;">
            <h2>Analysis Results</h2>
            <pre>{{ results }}</pre>
        </div>
        {% endif %}
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    return render_template_string(HTML_TEMPLATE)

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
        return render_template_string(HTML_TEMPLATE, results="Error: Please enter a folder path")
    
    # Handle relative paths from current working directory
    if not os.path.isabs(path):
        path = os.path.join(os.getcwd(), path)
    path = os.path.abspath(path)
    
    if not os.path.exists(path):
        return render_template_string(HTML_TEMPLATE, results=f"Error: Path '{path}' does not exist")
    
    if not os.path.isdir(path):
        return render_template_string(HTML_TEMPLATE, results=f"Error: '{path}' is not a directory")
    
    try:
        agent = AIAgentAnalyzer(path)
        results = agent.analyze_repository()  # Always generate risk analysis
        report = agent.generate_report(results)
        
        # Store results in session for Excel download
        session['last_results'] = results
        
        return render_template_string(HTML_TEMPLATE, results=report)
    except Exception as e:
        return render_template_string(HTML_TEMPLATE, results=f"Error analyzing path: {str(e)}")

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
        return jsonify({'error': f'Path does not exist: {path}'}), 400
    
    if not os.path.isdir(path):
        return jsonify({'error': f'Path is not a directory: {path}'}), 400
    
    try:
        agent = AIAgentAnalyzer(path)
        results = agent.analyze_repository()
        return jsonify(results)
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
    mitigations = {
        'password': 'Implement strong password policies and multi-factor authentication',
        'security': 'Conduct security audit and implement recommended security measures',
        'vulnerability': 'Apply security patches and conduct penetration testing',
        'risk': 'Perform risk assessment and implement risk management controls',
        'critical': 'Implement immediate containment measures and escalation procedures',
        'unauthorized': 'Implement access controls and authentication mechanisms',
        'threat': 'Deploy threat detection systems and incident response procedures',
        'compliance': 'Review compliance requirements and implement necessary controls',
        'warning': 'Investigate warning conditions and implement preventive measures'
    }
    return mitigations.get(keyword, 'Review and assess the identified issue for appropriate remediation')

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)