var config;

function login() {
    window.location.href = config.LOGIN_URL;
}

function me() {
    // read the XSRF cookie
    var xsrf = Cookies.get('XSRF-TOKEN');

    // get the profile info
    $.ajax({
        method: 'GET',
        url: config.ME_URL,
        headers: {
            'X-XSRF-TOKEN': xsrf
        },
        xhrFields: { withCredentials: true }
    }).done(function(data) {
        $('#results').html('');
        for (key in data) {
            var tr = $('<tr></tr>').appendTo('#results');
            $('<td></td>')
                .appendTo(tr)
                .text(key);
            $('<td></td>')
                .appendTo(tr)
                .text(data[key]);
        }
    });
}

$(document).ready(function() {
    // get configuration
    $.ajax({
        method: 'GET',
        url: 'https://api.plasne.com/api/config/wfe'
    }).done(function(data) {
        config = data;
        $('#loading').css('display', 'none');
        $('#interface').css('display', 'block');
    });
});
