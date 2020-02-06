var config;

function login() {
    window.location.href = config.LOGIN_URL;
}

function getUserByCookie() {
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
    })
        .done(function(data) {
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
        })
        .fail(function(_, _, errorThrown) {
            $('#results').html(errorThrown);
        });
}

function getUserByHeader() {
    // read the user cookie
    var user = Cookies.get('user');

    // get the profile info
    $.ajax({
        method: 'GET',
        url: config.ME_URL,
        headers: {
            Authorization: `Bearer ${user}`
        },
        xhrFields: { withCredentials: true }
    })
        .done(function(data) {
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
        })
        .fail(function(_, _, errorThrown) {
            $('#results').html(errorThrown);
        });
}

$(document).ready(function() {
    // get configuration
    $.ajax({
        method: 'GET',
        url: '/config'
    }).done(function(data) {
        config = data;
        $('#loading').css('display', 'none');
        $('#interface').css('display', 'block');
    });
});
