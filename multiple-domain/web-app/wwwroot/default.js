function getCookie(cname) {
    var name = cname + '=';
    var decodedCookie = decodeURIComponent(document.cookie);
    var ca = decodedCookie.split(';');
    for (var i = 0; i < ca.length; i++) {
        var c = ca[i];
        while (c.charAt(0) == ' ') {
            c = c.substring(1);
        }
        if (c.indexOf(name) == 0) {
            return c.substring(name.length, c.length);
        }
    }
    return '';
}

function getMenu() {
    const xsrf = getCookie('XSRF-TOKEN');
    const xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function () {
        if (this.readyState == 4) {
            if (this.status == 401) {
                redirectToLogin();
            } else if (this.status == 200) {
                document.getElementById('menu').innerHTML = '';
                const items = JSON.parse(this.responseText);
                for (let i = 0; i < items.length; i++) {
                    const item = items[i];
                    const a = document.createElement('a');
                    a.href = item.link;
                    a.innerText = item.name;
                    document.getElementById('menu').appendChild(a);
                    if (i < items.length - 1) {
                        const span = document.createElement('span');
                        span.innerText = ' | ';
                        document.getElementById('menu').appendChild(span);
                    }
                }
            } else {
                document.getElementById(
                    'output'
                ).innerHTML = `${this.status}: ${this.statusText}\n${this.responseText}`;
            }
        }
    };
    xhttp.open('GET', '/menu', true);
    xhttp.setRequestHeader('X-XSRF-TOKEN', xsrf);
    xhttp.send();
}

function redirectToLogin() {
    const xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function () {
        if (this.readyState == 4) {
            if (this.status == 200) {
                window.location.href = this.responseText;
            } else {
                document.getElementById(
                    'output'
                ).innerHTML = `${this.status}: ${this.statusText}\n${this.responseText}`;
            }
        }
    };
    xhttp.open('GET', '/login-link', true);
    xhttp.send();
}

function getStuff() {
    const xsrf = getCookie('XSRF-TOKEN');
    const xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function () {
        if (this.readyState == 4) {
            document.getElementById(
                'output'
            ).innerHTML = `${this.status}: ${this.statusText}\n${this.responseText}`;
        }
    };
    xhttp.open('GET', '/stuff', true);
    xhttp.setRequestHeader('X-XSRF-TOKEN', xsrf);
    xhttp.send();
}

document.addEventListener('DOMContentLoaded', function () {
    getMenu();
});
