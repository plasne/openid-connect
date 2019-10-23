// references
const express = require('express');
const cookieParser = require('cookie-parser');
const request = require('request-promise-native');
const jwt = require('jsonwebtoken');
const app = express();

// variables
const port = 5600;

// cookie middleware
app.use(cookieParser());

// authentication middleware
app.use(async (req, res, next) => {
    // look for user cookie
    if (!req.cookies.user) {
        res.status(401).send();
        return;
    }

    // look for XSRF header (headers are always lowercase)
    if (!req.headers['x-xsrf-token']) {
        res.status(401).send();
        return;
    }

    var jwksClient = require('jwks-rsa');
    var client = jwksClient({
        jwksUri: 'http://localhost:5100/api/auth/keys'
    });
    function getKey(header, callback) {
        client.getSigningKey(header.kid, function(err, key) {
            var signingKey = key.publicKey || key.rsaPublicKey;
            callback(null, signingKey);
        });
    }

    jwt.verify(req.cookies.user, getKey, {}, function(err, decoded) {
        console.log(decoded); // bar
    });

    next();
});

// identity endpoint
app.get('/api/identity/me', (req, res) => {
    res.status(200).send();
});

// start listening
app.listen(port, () => console.log(`listening on port ${port}...`));
