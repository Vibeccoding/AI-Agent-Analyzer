from document_analyzer import AIAgentAnalyzer

# Quick test script
agent = AIAgentAnalyzer(".")
results = agent.analyze_repository()
report = agent.generate_report(results)
print(report)