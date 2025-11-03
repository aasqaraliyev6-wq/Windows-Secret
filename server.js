// Simple Node.js server for additional security
const express = require('express');
const path = require('path');
const app = express();
const port = 3000;

// Static files
app.use(express.static('public'));

// Main route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// API route for password verification (optional)
app.post('/verify', express.json(), (req, res) => {
    const { password } = req.body;
    // Add your custom verification logic here
    if (password === 'mysecret2024') {
        res.json({ success: true });
    } else {
        res.json({ success: false });
    }
});

app.listen(port, () => {
    console.log(`Secure server running at http://localhost:${port}`);
});
