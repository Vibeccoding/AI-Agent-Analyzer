import os
import json
from pathlib import Path
from typing import List, Dict, Any
import re

class AIAgentAnalyzer:
    def __init__(self, root_path: str):
        self.root_path = Path(root_path)
        self.supported_extensions = set()  # Empty set means scan all file types
        self.risk_keywords = [
            'risk', 'threat', 'vulnerability', 'security', 'breach', 'failure', 'error',
            'critical', 'urgent', 'warning', 'danger', 'issue', 'problem', 'concern',
            'compliance', 'audit', 'violation', 'unauthorized', 'malicious', 'attack',
            'deprecated', 'legacy', 'outdated', 'insecure', 'exposed', 'leak', 'injection',
            'overflow', 'denial', 'privilege', 'escalation', 'backdoor', 'trojan', 'virus',
            'phishing', 'ransomware', 'data loss', 'corruption', 'downtime', 'outage'
        ]
    
    def recursive_search(self) -> List[Path]:
        """Recursively search for documents in the agent repository"""
        documents = []
        for file_path in self.root_path.rglob('*'):
            if file_path.is_file():
                documents.append(file_path)
        return documents
    
    def read_document(self, file_path: Path) -> str:
        """Read document content from any file type"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                # Skip empty files or files with only binary content
                if not content.strip() or len([c for c in content[:100] if ord(c) < 32 and c not in '\n\r\t']) > 50:
                    return f"[Binary/Empty file: {file_path.name}]"
                return content
        except Exception as e:
            return f"[Error reading {file_path.name}]: {str(e)}"
    
    def summarize_document(self, content: str, file_name: str) -> str:
        """Generate a summary of the agent document content"""
        if not content:
            return f"Document: {file_name} | Status: Empty file"
        
        if content.startswith('['):
            return f"Document: {file_name} | Status: {content}"
        
        lines = content.split('\n')
        non_empty_lines = [line.strip() for line in lines if line.strip()]
        
        if len(non_empty_lines) == 0:
            return f"Document: {file_name} | Status: No readable content"
        
        # Extract key information
        word_count = len(content.split())
        line_count = len(non_empty_lines)
        
        # Get first few meaningful lines as summary
        summary_lines = non_empty_lines[:3]
        summary = ' '.join(summary_lines)
        
        if len(summary) > 200:
            summary = summary[:200] + "..."
        
        return f"Document: {file_name} | Lines: {line_count} | Words: {word_count} | Summary: {summary}"
    
    def identify_risks(self, content: str, file_name: str) -> List[Dict[str, Any]]:
        """Identify risk items in the agent document"""
        risks = []
        if not content:
            return risks
        
        # Handle binary/error files by checking content
        if content.startswith('['):
            # Still check if the error message itself contains risk keywords
            content_lower = content.lower()
            for keyword in self.risk_keywords:
                if keyword in content_lower:
                    risks.append({
                        'file': file_name,
                        'line': 1,
                        'keyword': keyword,
                        'context': content[:100],
                        'severity': self._assess_severity(keyword)
                    })
            return risks
        
        lines = content.split('\n')
        original_lines = lines.copy()
        lines_lower = [line.lower() for line in lines]
        
        for i, line_lower in enumerate(lines_lower, 1):
            for keyword in self.risk_keywords:
                if keyword in line_lower:
                    # Use original line for context (preserve case)
                    original_line = original_lines[i-1]
                    keyword_pos = line_lower.find(keyword)
                    context_start = max(0, keyword_pos - 50)
                    context_end = min(len(original_line), keyword_pos + len(keyword) + 50)
                    context = original_line[context_start:context_end].strip()
                    
                    risks.append({
                        'file': file_name,
                        'line': i,
                        'keyword': keyword,
                        'context': context,
                        'severity': self._assess_severity(keyword)
                    })
                    break  # Avoid duplicate risks for same line
        
        return risks
    
    def _assess_severity(self, keyword: str) -> str:
        """Assess risk severity based on keyword"""
        high_severity = {'critical', 'urgent', 'breach', 'attack', 'malicious', 'violation'}
        medium_severity = {'risk', 'threat', 'vulnerability', 'security', 'failure'}
        
        if keyword in high_severity:
            return 'HIGH'
        elif keyword in medium_severity:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def analyze_repository(self) -> Dict[str, Any]:
        """Main method to analyze the entire agent repository"""
        print(f"Starting AI agent analysis of repository: {self.root_path}")
        
        # Step 1: Recursive search
        documents = self.recursive_search()
        print(f"Found {len(documents)} documents")
        
        # Step 2: Process each document
        summaries = []
        all_risks = []
        
        for doc_path in documents:
            content = self.read_document(doc_path)
            
            # Generate summary
            summary = self.summarize_document(content, doc_path.name)
            summaries.append({
                'file': str(doc_path.relative_to(self.root_path)),
                'summary': summary
            })
            
            # Identify risks
            risks = self.identify_risks(content, doc_path.name)
            all_risks.extend(risks)
        
        # Step 3: Compile results
        results = {
            'repository_path': str(self.root_path),
            'total_documents': len(documents),
            'document_summaries': summaries
        }
        
        # Add risk analysis
        results['risk_items'] = {
            'total_risks': len(all_risks),
            'high_severity': [r for r in all_risks if r['severity'] == 'HIGH'],
            'medium_severity': [r for r in all_risks if r['severity'] == 'MEDIUM'],
            'low_severity': [r for r in all_risks if r['severity'] == 'LOW'],
            'all_risks': all_risks
        }
        
        return results
    
    def generate_report(self, results: Dict[str, Any]) -> str:
        """Generate a formatted AI agent report"""
        report = []
        report.append("=" * 60)
        report.append("AI AGENT ANALYSIS REPORT")
        report.append("=" * 60)
        report.append(f"Repository: {results['repository_path']}")
        report.append(f"Total Documents Analyzed: {results['total_documents']}")
        report.append("")
        
        # Document Summaries
        report.append("DOCUMENT SUMMARIES:")
        report.append("-" * 40)
        for summary in results['document_summaries']:
            report.append(f"• {summary['summary']}")
        report.append("")
        
        # Risk Analysis (only if available)
        if 'risk_items' in results:
            risk_data = results['risk_items']
            report.append("RISK ANALYSIS:")
            report.append("-" * 40)
            report.append(f"Total Risk Items Found: {risk_data['total_risks']}")
            report.append(f"High Severity: {len(risk_data['high_severity'])}")
            report.append(f"Medium Severity: {len(risk_data['medium_severity'])}")
            report.append(f"Low Severity: {len(risk_data['low_severity'])}")
            report.append("")
            
            # Detailed Risk Items
            if risk_data['all_risks']:
                report.append("DETAILED RISK ITEMS:")
                report.append("-" * 40)
                for risk in sorted(risk_data['all_risks'], key=lambda x: x['severity'], reverse=True):
                    report.append(f"[{risk['severity']}] {risk['file']} (Line {risk['line']})")
                    report.append(f"  Keyword: {risk['keyword']}")
                    report.append(f"  Context: {risk['context']}")
                    report.append("")
        else:
            report.append("RISK ANALYSIS: Skipped (not requested)")
            report.append("")
        
        return "\n".join(report)

def main():
    # Example usage
    repo_path = input("Enter repository path (or press Enter for current directory): ").strip()
    if not repo_path:
        repo_path = "."
    
    agent = AIAgentAnalyzer(repo_path)
    results = agent.analyze_repository()
    
    # Generate and display report
    report = agent.generate_report(results)
    print(report)
    
    # Save results to JSON
    with open('analysis_results.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\nDetailed results saved to: analysis_results.json")

if __name__ == "__main__":
    main()