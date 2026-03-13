const https = require('https');

const postData = JSON.stringify({
    service_id: "service_mgex0rv",
    template_id: "template_2ybw8hm",
    user_id: "yP3m8DxxcW8eqkV6t",
    template_params: {
        verification_code: "123456",
        to_email: "vadealok55@gmail.com",
        system_name: "NexusGuard"
    }
});

const options = {
    hostname: 'api.emailjs.com',
    port: 443,
    path: '/api/v1.0/email/send',
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
        'Origin': 'http://localhost:5173',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    }
};

const req = https.request(options, (res) => {
    let responseBody = '';

    res.on('data', (chunk) => {
        responseBody += chunk;
    });

    res.on('end', () => {
        console.log(`STATUS: ${res.statusCode}`);
        console.log(`RESPONSE: ${responseBody}`);
    });
});

req.on('error', (e) => {
    console.error(`Problem with request: ${e.message}`);
});

req.write(postData);
req.end();
