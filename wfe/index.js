// includes
const express = require('express');
const axios = require('axios');
require('dotenv').config();

// host www
const app = express();
app.use(express.static('www'));

// startup on the appropriate port
var port = process.env.PORT || 80;
var hostUrl = process.env.HOST_URL;
if (hostUrl) {
    var s = hostUrl.split(':');
    if (s.length > 2) port = s[2];
}
app.listen(port, () => {
    console.log(`app listening on port ${port}...`);
});

// set default file
app.get('/', (_, res) => {
    res.redirect('./default.html');
});

app.get('/config', (_, res) => {
    axios
        .get(process.env.CONFIG_URL)
        .then(function(response) {
            res.send(response.data);
        })
        .catch(function(error) {
            res.status(500).send(error.message);
        });
});
