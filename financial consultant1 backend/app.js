// JavaScript application with potential vulnerabilities
const express = require('express');
const app = express();

// Critical security flaw: No authentication
app.get('/api/data', (req, res) => {
    // Risk of unauthorized access to sensitive data
    res.json({users: getAllUsers()});
});

// Warning: SQL injection vulnerability
function getUser(id) {
    return db.query(`SELECT * FROM users WHERE id = ${id}`);
}

// Compliance violation: No input validation
app.post('/transfer', (req, res) => {
    // Threat: Direct database manipulation
    executeTransfer(req.body.amount, req.body.account);
});