function hello() {
    // read the XSRF cookie
    var xsrf = Cookies.get('XSRF-TOKEN');

    // send the XSRF on the header
    $.ajax({
        method: 'GET',
        url: 'https://pelasne-web.azurewebsites.net/api/auth/hello',
        headers: {
            'X-XSRF-TOKEN': xsrf
        },
        xhrFields: { withCredentials: true }
    }).done(function(data) {
        $('#results').append(data);
    });
}

$(document).ready(function() {});
