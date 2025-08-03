# AI Document Analyzer - Local Deployment

## Quick Start
1. Double-click `start.bat` 
2. Open browser to `http://127.0.0.1:5000`
3. Login with credentials (admin/password)
4. Enter repository path and click "Analyze Documents"

## Login Credentials
- admin / password
- user1 / demo123
- analyst / analyze2024

## API Usage
POST to `http://127.0.0.1:5000/api/analyze`
```json
Headers: {"Authorization": "Bearer admin:password"}
Body: {"path": "./documents"}
```

## Features
- User authentication with login screen
- Recursive document search
- Document summarization  
- Risk item identification
- Responsive web UI + REST API