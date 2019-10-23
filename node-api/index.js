// references
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const jwks = require('jwks-rsa');
const request = require('request-promise-native');
const util = require('util');

// variables
const app = express();
const port = 5600;
const KEYS_URL = 'http://localhost:5100/api/auth/keys';
const REISSUE_URL = 'http://localhost:5100/api/auth/reissue';
const BASE_DOMAIN = 'localhost';

// establish a caching key reader
const jwksclient = jwks({
    cache: true,
    jwksUri: KEYS_URL,
    rateLimit: true
});

// promisify
const verifyAsync = util.promisify(jwt.verify);
const getSigningKeyAsync = util.promisify(jwksclient.getSigningKey);

// cookie middleware
app.use(cookieParser());

// authentication middleware
app.use(async (req, res, next) => {
    try {
        // look for user cookie
        if (!req.cookies.user) {
            console.warn('user cookie is missing');
            res.status(401).send();
            return;
        }

        // look for XSRF header
        if (!req.get('X-XSRF-TOKEN')) {
            console.warn('X-XSRF-TOKEN header is missing');
            res.status(401).send();
            return;
        }

        // check for expiration and reissue
        let token = req.cookies.user;
        const decoded = jwt.decode(token);
        const now = Math.floor(Date.now() / 1000);
        if (now > decoded.exp) {
            console.log('token is expired, requesting reissue...');
            token = await request({
                json: true,
                method: 'POST',
                uri: REISSUE_URL,
                form: {
                    token: req.cookies.user
                }
            });
            res.cookie('user', token, {
                httpOnly: true,
                secure: false,
                domain: BASE_DOMAIN,
                path: '/'
            });
            console.log('successfully reissued token.');
        }

        // get the public cert to validate the signature
        const getKey = async (header, callback) => {
            try {
                const key = await getSigningKeyAsync(header.kid);
                const signingKey = key.publicKey || key.rsaPublicKey;
                callback(null, signingKey);
            } catch (err) {
                callback(err);
            }
        };

        // verify the JWT signature
        let verified = null;
        try {
            verified = await verifyAsync(token, getKey, {});
        } catch (err) {
            console.warn('signature validation failed...');
            console.error(err);
            res.status(401).send();
            return;
        }

        // make sure the XSRF matches
        if (verified.xsrf !== req.get('X-XSRF-TOKEN')) {
            console.warn('XSRF did not match');
            res.status(401).send();
            return;
        }

        // add isInRole()
        res.locals.isInRole = (role, scope) => {
            const claim = scope ? `${scope}-roles` : 'roles';
            if (verified[claim]) {
                const roles = verified[claim].split(',');
                return roles.includes(role);
            } else {
                return false;
            }
        };

        // next
        res.locals.auth = verified;
        console.log('user authenticated successfully.');
        next();
    } catch (err) {
        console.warn('application exception...');
        console.error(err);
        res.status(500).send();
    }
});

// identity endpoint
app.get('/api/identity/me', (req, res) => {
    /* sample showing a role check
    if (!res.locals.isInRole('user', 'e8a64bb9-9e42-4da7-97c2-ee8d4a8cd217')) {
        res.status(403).send();
        return;
    }
    */

    // return user claims
    const me = {};
    const filter = ['xsrf', 'old', 'exp', 'iss', 'aud'];
    for (const key in res.locals.auth) {
        if (!filter.includes(key)) me[key] = res.locals.auth[key];
    }
    res.status(200).send(me);
});

// start listening
app.listen(port, () => console.log(`listening on port ${port}...`));
