# XSS and XSRF Protection

This pattern is designed to address Cross-Site Scripting (XSS) and Cross-Site Request Forgery (XSRF). An example of each attack is below. Keep in mind that there is never perfect security, but the techniques employed here can mitigate the common concerns.

You can protect a cookie containing a token against a malicious actor using an XSS attack effectively by marking it as HttpOnly. However, when you do that, your JavaScript can no longer read the cookie to send the token as an Authorization Bearer token in the header, so the cookie must be automatically delivered with each service call. Sending the cookie on every service call opens your service up to an XSRF attack.

The approach used by this solution is two-fold. Two cookies are issued:

-   session_token - contained in a cookie marked HttpOnly

-   XSRF-TOKEN - contained in a cookie readable by JavaScript

Authentication is only accepted when the cookie containing the session_token is passed AND there is an X-XSRF-TOKEN header (obtained by reading the cookie containing the XSRF-TOKEN value via JavaScript). This combination approach ensures that this solution is resilient versus these common attacks.

## Example of an XSS Hack

1. You prompt the user to enter their name in an input field.

1. The hacker instead pastes a malicious JavaScript.

1. You display the "name" but in fact are prompting the browser to run the JavaScript.

1. The JavaScript reads all cookies looking for an access_token or session_token.

1. The attacker uses the token to do something unintended.

## Example of an XSRF Hack

1. The attacker assumes that you send cookies with authentication on each API REST call.

1. The attacker assumes the user has recently logged into the application so the cookie might still provide authentication.

1. The attacker uses a phishing attack to get the user to click on a link that will initiate an API REST call to your service.

1. The cookie with authentication is sent to your service and an unintended action is performed under the user's authority.
