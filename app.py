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
</head>
<body>
    <h1>AI Agent Analyzer</h1>
    <a href="/logout">Logout</a>
    
    <form method="POST" action="/analyze">
        <label>Repository Path:</label><br>
        <input type="text" name="path" placeholder="Enter folder path">
        <button type="submit">Analyze Documents</button>
    </form>
    
    <h2>Download Options:</h2>
    <button onclick="downloadExcel()" style="background:red; color:white; padding:10px; margin:10px;">Download Risk Report</button>
    <button onclick="downloadSummary()" style="background:blue; color:white; padding:10px; margin:10px;">Summarize Documents</button>
    
    <script>
        document.getElementById('folderSelect').addEventListener('change', function(e) {
            if (e.target.files.length > 0) {
                const path = e.target.files[0].webkitRelativePath.split('/')[0];
                document.getElementById('folderPath').value = './' + path;
            }
        });
        
        function downloadExcel() {
            window.location.href = '/download-excel';
        }
        
        function downloadSummary() {
            window.location.href = '/download-summary';
        }
        
        // Show download buttons if results exist
        document.addEventListener('DOMContentLoaded', function() {
            setTimeout(function() {
                if (document.querySelector('pre')) {
                    document.getElementById('downloadBtn').style.display = 'inline-block';
                    document.getElementById('summaryBtn').style.display = 'inline-block';
                }
            }, 100);
        });
        
        // Also check after form submission
        if (document.querySelector('pre')) {
            document.getElementById('downloadBtn').style.display = 'inline-block';
            document.getElementById('summaryBtn').style.display = 'inline-block';
        }
    </script>
    <div style="margin-top:10px; font-size:12px; color:#666;">
        Examples: C:\\Users\\Documents, ./project-docs, /home/user/files
    </div>
    {% if results %}
    <hr>
    <h2>Analysis Results</h2>
    <pre>{{ results }}</pre>
    {% endif %}
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
    
    # Expand user path and resolve relative paths
    path = os.path.expanduser(path)
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
    
    # Expand and validate path
    path = os.path.expanduser(path)
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
        return redirect(url_for('login'))
    
    results = session['last_results']
    
    risks = results['risk_items']['all_risks']
    
    # Create DataFrame
    df = pd.DataFrame(risks)
    
    # Add metadata
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'risk_analysis_{timestamp}.xlsx'
    filepath = os.path.join(os.getcwd(), filename)
    
    # Write to Excel
    with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Risk Analysis', index=False)
        
        # Add summary sheet
        summary_data = {
            'Metric': ['Total Documents', 'Total Risks', 'High Severity', 'Medium Severity', 'Low Severity'],
            'Count': [
                results['total_documents'],
                results['risk_items']['total_risks'],
                len(results['risk_items']['high_severity']),
                len(results['risk_items']['medium_severity']),
                len(results['risk_items']['low_severity'])
            ]
        }
        summary_df = pd.DataFrame(summary_data)
        summary_df.to_excel(writer, sheet_name='Summary', index=False)
    
    return send_file(filepath, as_attachment=True, download_name=filename)

@app.route('/download-summary')
def download_summary():
    if 'logged_in' not in session or 'last_results' not in session:
        return redirect(url_for('login'))
    
    results = session['last_results']
    summaries = results['document_summaries']
    
    # Create PDF
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'document_summary_{timestamp}.pdf'
    filepath = os.path.join(os.getcwd(), filename)
    
    doc = SimpleDocTemplate(filepath, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    title = Paragraph("Document Summary Report", styles['Title'])
    story.append(title)
    story.append(Spacer(1, 12))
    
    # Repository info
    repo_info = Paragraph(f"Repository: {results['repository_path']}", styles['Normal'])
    story.append(repo_info)
    total_docs = Paragraph(f"Total Documents: {results['total_documents']}", styles['Normal'])
    story.append(total_docs)
    story.append(Spacer(1, 12))
    
    # Document summaries
    for summary in summaries:
        file_para = Paragraph(f"<b>File:</b> {summary['file']}", styles['Normal'])
        story.append(file_para)
        summary_para = Paragraph(f"<b>Summary:</b> {summary['summary']}", styles['Normal'])
        story.append(summary_para)
        story.append(Spacer(1, 12))
    
    doc.build(story)
    return send_file(filepath, as_attachment=True, download_name=filename)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)