from document_analyzer import AIAgentAnalyzer
import os

# Test different path formats
test_paths = [
    ".",  # Current directory
    "./sample_documents",  # Relative path
    os.path.expanduser("~/Documents"),  # User home directory
    "C:\\Users\\207295\\Downloads\\Knowledge_Transition_Framework\\sample_documents"  # Absolute path
]

for path in test_paths:
    print(f"\nTesting path: {path}")
    expanded_path = os.path.expanduser(path)
    absolute_path = os.path.abspath(expanded_path)
    print(f"Expanded to: {absolute_path}")
    
    if os.path.exists(absolute_path):
        print("✓ Path exists")
        if os.path.isdir(absolute_path):
            print("✓ Is directory")
        else:
            print("✗ Not a directory")
    else:
        print("✗ Path does not exist")