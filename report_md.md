# ZAP Scanning Report


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 3 |
| Low | 6 |
| Informational | 5 |




## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| Application Error Disclosure | Medium | 1 |
| Content Security Policy (CSP) Header Not Set | Medium | 4 |
| Missing Anti-clickjacking Header | Medium | 2 |
| Incomplete or No Cache-control Header Set | Low | 2 |
| Permissions Policy Header Not Set | Low | 11 |
| Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) | Low | 4 |
| Strict-Transport-Security Header Not Set | Low | 11 |
| Timestamp Disclosure - Unix | Low | 4 |
| X-Content-Type-Options Header Missing | Low | 11 |
| Base64 Disclosure | Informational | 7 |
| Information Disclosure - Suspicious Comments | Informational | 9 |
| Modern Web Application | Informational | 6 |
| Storable and Cacheable Content | Informational | 10 |
| Storable but Non-Cacheable Content | Informational | 1 |




## Alert Detail



### [ Application Error Disclosure ](https://www.zaproxy.org/docs/alerts/90022/)



##### Medium (Medium)

### Description

This page contains an error/warning message that may disclose sensitive information like the location of the file that produced the unhandled exception. This information can be used to launch further attacks against the web application. The alert could be a false positive if the error message is found inside a documentation page.

* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/main-c4f2541b93e4ae8b71f8.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Internal Server Error`

Instances: 1

### Solution

Review the source code of this page. Implement custom error pages. Consider implementing a mechanism to provide a unique error reference/identifier to the client (browser) while logging the details on the server side and not exposing them to the user.

### Reference



#### CWE Id: [ 200 ](https://cwe.mitre.org/data/definitions/200.html)


#### WASC Id: 13

#### Source ID: 3

### [ Content Security Policy (CSP) Header Not Set ](https://www.zaproxy.org/docs/alerts/10038/)



##### Medium (High)

### Description

Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

* URL: https://realm-registry.apps.silver.devops.gov.bc.ca
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``

Instances: 4

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header, to achieve optimal browser support: "Content-Security-Policy" for Chrome 25+, Firefox 23+ and Safari 7+, "X-Content-Security-Policy" for Firefox 4.0+ and Internet Explorer 10+, and "X-WebKit-CSP" for Chrome 14+ and Safari 6+.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy ](https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy)
* [ https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
* [ http://www.w3.org/TR/CSP/ ](http://www.w3.org/TR/CSP/)
* [ http://w3c.github.io/webappsec/specs/content-security-policy/csp-specification.dev.html ](http://w3c.github.io/webappsec/specs/content-security-policy/csp-specification.dev.html)
* [ http://www.html5rocks.com/en/tutorials/security/content-security-policy/ ](http://www.html5rocks.com/en/tutorials/security/content-security-policy/)
* [ http://caniuse.com/#feat=contentsecuritypolicy ](http://caniuse.com/#feat=contentsecuritypolicy)
* [ http://content-security-policy.com/ ](http://content-security-policy.com/)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Missing Anti-clickjacking Header ](https://www.zaproxy.org/docs/alerts/10020/)



##### Medium (Medium)

### Description

The response does not include either Content-Security-Policy with 'frame-ancestors' directive or X-Frame-Options to protect against 'ClickJacking' attacks.

* URL: https://realm-registry.apps.silver.devops.gov.bc.ca
  * Method: `GET`
  * Parameter: `X-Frame-Options`
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/
  * Method: `GET`
  * Parameter: `X-Frame-Options`
  * Attack: ``
  * Evidence: ``

Instances: 2

### Solution

Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers. Ensure one of them is set on all web pages returned by your site/app.
If you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. Alternatively consider implementing Content Security Policy's "frame-ancestors" directive.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)


#### CWE Id: [ 1021 ](https://cwe.mitre.org/data/definitions/1021.html)


#### WASC Id: 15

#### Source ID: 3

### [ Incomplete or No Cache-control Header Set ](https://www.zaproxy.org/docs/alerts/10015/)



##### Low (Medium)

### Description

The cache-control header has not been set properly or is missing, allowing the browser and proxies to cache content.

* URL: https://realm-registry.apps.silver.devops.gov.bc.ca
  * Method: `GET`
  * Parameter: `Cache-Control`
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/
  * Method: `GET`
  * Parameter: `Cache-Control`
  * Attack: ``
  * Evidence: ``

Instances: 2

### Solution

Whenever possible ensure the cache-control HTTP header is set with no-cache, no-store, must-revalidate.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching ](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching)
* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control)


#### CWE Id: [ 525 ](https://cwe.mitre.org/data/definitions/525.html)


#### WASC Id: 13

#### Source ID: 3

### [ Permissions Policy Header Not Set ](https://www.zaproxy.org/docs/alerts/10063/)



##### Low (Medium)

### Description

Permissions Policy Header is an added layer of security that helps to restrict from unauthorized access or usage of browser/client features by web resources. This policy ensures the user privacy by limiting or specifying the features of the browsers can be used by the web resources. Permissions Policy provides a set of standard HTTP headers that allow website owners to limit which features of browsers can be used by the page such as camera, microphone, location, full screen etc.

* URL: https://realm-registry.apps.silver.devops.gov.bc.ca
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/719GE62jyZ2HQnFUemVuV/_buildManifest.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/framework-2191d16384373197bc0a.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/main-c4f2541b93e4ae8b71f8.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/pages/_app-b3da07b0b7b0eb1855f2.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/pages/index-f442bfa1ca39bb88c0b8.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/polyfills-a40ef1678bae11e696dba45124eadd70.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/webpack-613fd858cdb9cf2af3be.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``

Instances: 11

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to set the Permissions-Policy header.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy)
* [ https://developers.google.com/web/updates/2018/06/feature-policy ](https://developers.google.com/web/updates/2018/06/feature-policy)
* [ https://scotthelme.co.uk/a-new-security-header-feature-policy/ ](https://scotthelme.co.uk/a-new-security-header-feature-policy/)
* [ https://w3c.github.io/webappsec-feature-policy/ ](https://w3c.github.io/webappsec-feature-policy/)
* [ https://www.smashingmagazine.com/2018/12/feature-policy/ ](https://www.smashingmagazine.com/2018/12/feature-policy/)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) ](https://www.zaproxy.org/docs/alerts/10037/)



##### Low (Medium)

### Description

The web/application server is leaking information via one or more "X-Powered-By" HTTP response headers. Access to such information may facilitate attackers identifying other frameworks/components your web application is reliant upon and the vulnerabilities such components may be subject to.

* URL: https://realm-registry.apps.silver.devops.gov.bc.ca
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `x-powered-by: Next.js`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `x-powered-by: Next.js`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `x-powered-by: Next.js`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `x-powered-by: Next.js`

Instances: 4

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to suppress "X-Powered-By" headers.

### Reference


* [ http://blogs.msdn.com/b/varunm/archive/2013/04/23/remove-unwanted-http-response-headers.aspx ](http://blogs.msdn.com/b/varunm/archive/2013/04/23/remove-unwanted-http-response-headers.aspx)
* [ http://www.troyhunt.com/2012/02/shhh-dont-let-your-response-headers.html ](http://www.troyhunt.com/2012/02/shhh-dont-let-your-response-headers.html)


#### CWE Id: [ 200 ](https://cwe.mitre.org/data/definitions/200.html)


#### WASC Id: 13

#### Source ID: 3

### [ Strict-Transport-Security Header Not Set ](https://www.zaproxy.org/docs/alerts/10035/)



##### Low (High)

### Description

HTTP Strict Transport Security (HSTS) is a web security policy mechanism whereby a web server declares that complying user agents (such as a web browser) are to interact with it using only secure HTTPS connections (i.e. HTTP layered over TLS/SSL). HSTS is an IETF standards track protocol and is specified in RFC 6797.

* URL: https://realm-registry.apps.silver.devops.gov.bc.ca
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/framework-2191d16384373197bc0a.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/main-c4f2541b93e4ae8b71f8.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/pages/_app-b3da07b0b7b0eb1855f2.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/polyfills-a40ef1678bae11e696dba45124eadd70.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/webpack-613fd858cdb9cf2af3be.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/css/4b83d2c75330f0e20ee0.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/bcid-favicon-32x32.png
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``

Instances: 11

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to enforce Strict-Transport-Security.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
* [ https://owasp.org/www-community/Security_Headers ](https://owasp.org/www-community/Security_Headers)
* [ http://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security ](http://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security)
* [ http://caniuse.com/stricttransportsecurity ](http://caniuse.com/stricttransportsecurity)
* [ http://tools.ietf.org/html/rfc6797 ](http://tools.ietf.org/html/rfc6797)


#### CWE Id: [ 319 ](https://cwe.mitre.org/data/definitions/319.html)


#### WASC Id: 15

#### Source ID: 3

### [ Timestamp Disclosure - Unix ](https://www.zaproxy.org/docs/alerts/10096/)



##### Low (Low)

### Description

A timestamp was disclosed by the application/web server - Unix

* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/css/4b83d2c75330f0e20ee0.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `23198754`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/css/4b83d2c75330f0e20ee0.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `23212529`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/css/4b83d2c75330f0e20ee0.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `33333333`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/css/4b83d2c75330f0e20ee0.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `66666667`

Instances: 4

### Solution

Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.

### Reference


* [ http://projects.webappsec.org/w/page/13246936/Information%20Leakage ](http://projects.webappsec.org/w/page/13246936/Information%20Leakage)


#### CWE Id: [ 200 ](https://cwe.mitre.org/data/definitions/200.html)


#### WASC Id: 13

#### Source ID: 3

### [ X-Content-Type-Options Header Missing ](https://www.zaproxy.org/docs/alerts/10021/)



##### Low (Medium)

### Description

The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.

* URL: https://realm-registry.apps.silver.devops.gov.bc.ca
  * Method: `GET`
  * Parameter: `X-Content-Type-Options`
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/
  * Method: `GET`
  * Parameter: `X-Content-Type-Options`
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/719GE62jyZ2HQnFUemVuV/_buildManifest.js
  * Method: `GET`
  * Parameter: `X-Content-Type-Options`
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/framework-2191d16384373197bc0a.js
  * Method: `GET`
  * Parameter: `X-Content-Type-Options`
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/main-c4f2541b93e4ae8b71f8.js
  * Method: `GET`
  * Parameter: `X-Content-Type-Options`
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/pages/_app-b3da07b0b7b0eb1855f2.js
  * Method: `GET`
  * Parameter: `X-Content-Type-Options`
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/pages/index-f442bfa1ca39bb88c0b8.js
  * Method: `GET`
  * Parameter: `X-Content-Type-Options`
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/polyfills-a40ef1678bae11e696dba45124eadd70.js
  * Method: `GET`
  * Parameter: `X-Content-Type-Options`
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/webpack-613fd858cdb9cf2af3be.js
  * Method: `GET`
  * Parameter: `X-Content-Type-Options`
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/css/4b83d2c75330f0e20ee0.css
  * Method: `GET`
  * Parameter: `X-Content-Type-Options`
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/bcid-favicon-32x32.png
  * Method: `GET`
  * Parameter: `X-Content-Type-Options`
  * Attack: ``
  * Evidence: ``

Instances: 11

### Solution

Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.
If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.

### Reference


* [ http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx ](http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx)
* [ https://owasp.org/www-community/Security_Headers ](https://owasp.org/www-community/Security_Headers)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Base64 Disclosure ](https://www.zaproxy.org/docs/alerts/10094/)



##### Informational (Medium)

### Description

Base64 encoded data was disclosed by the application/web server. Note: in the interests of performance not all base64 strings in the response were analyzed individually, the entire response should be looked at by the analyst/security team/developer(s).

* URL: https://realm-registry.apps.silver.devops.gov.bc.ca
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `ca80-VoyaFZ5cNPEsTelFHc5hJEIwTeg`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `ca80-VoyaFZ5cNPEsTelFHc5hJEIwTeg`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/image%3Fq=75&url=%252F_next%252Fstatic%252Fimage%252Fpublic%252Fhome-right.cc430f38e775dbf6b365453645065048.png&w=3840
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Jchm2dfIBnwzkOJ9Tp0hA-rHiOEErfvMAEk3EEo22pw=`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/pages/_app-b3da07b0b7b0eb1855f2.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/pages/index-f442bfa1ca39bb88c0b8.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `bad8-I5Wgm1/v/iABHo2GjmBuzktB0BY`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `bad8-I5Wgm1/v/iABHo2GjmBuzktB0BY`

Instances: 7

### Solution

Manually confirm that the Base64 data does not leak sensitive information, and that the data cannot be aggregated/used to exploit other vulnerabilities.

### Reference


* [ http://projects.webappsec.org/w/page/13246936/Information%20Leakage ](http://projects.webappsec.org/w/page/13246936/Information%20Leakage)


#### CWE Id: [ 200 ](https://cwe.mitre.org/data/definitions/200.html)


#### WASC Id: 13

#### Source ID: 3

### [ Information Disclosure - Suspicious Comments ](https://www.zaproxy.org/docs/alerts/10027/)



##### Informational (Low)

### Description

The response appears to contain suspicious comments which may help an attacker. Note: Matches made within script blocks or files are against the entire content not only comments.

* URL: https://realm-registry.apps.silver.devops.gov.bc.ca
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `query`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `query`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/framework-2191d16384373197bc0a.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `select`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/main-c4f2541b93e4ae8b71f8.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `query`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/pages/_app-b3da07b0b7b0eb1855f2.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `admin`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/pages/index-f442bfa1ca39bb88c0b8.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `from`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/polyfills-a40ef1678bae11e696dba45124eadd70.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `query`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `query`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `query`

Instances: 9

### Solution

Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.

### Reference



#### CWE Id: [ 200 ](https://cwe.mitre.org/data/definitions/200.html)


#### WASC Id: 13

#### Source ID: 3

### [ Modern Web Application ](https://www.zaproxy.org/docs/alerts/10109/)



##### Informational (Medium)

### Description

The application appears to be a modern web application. If you need to explore it automatically then the Ajax Spider may well be more effective than the standard one.

* URL: https://realm-registry.apps.silver.devops.gov.bc.ca
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<noscript data-n-css=""></noscript>`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<noscript data-n-css=""></noscript>`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/framework-2191d16384373197bc0a.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script>`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/polyfills-a40ef1678bae11e696dba45124eadd70.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script>`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<noscript data-n-css=""></noscript>`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<noscript data-n-css=""></noscript>`

Instances: 6

### Solution

This is an informational alert and so no changes are required.

### Reference




#### Source ID: 3

### [ Storable and Cacheable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are storable by caching components such as proxy servers, and may be retrieved directly from the cache, rather than from the origin server by the caching servers, in response to similar requests from other users.  If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where "shared" caching servers such as "proxy" caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance.

* URL: https://realm-registry.apps.silver.devops.gov.bc.ca
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/framework-2191d16384373197bc0a.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=31536000`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/main-c4f2541b93e4ae8b71f8.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=31536000`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/pages/_app-b3da07b0b7b0eb1855f2.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=31536000`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/polyfills-a40ef1678bae11e696dba45124eadd70.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=31536000`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/chunks/webpack-613fd858cdb9cf2af3be.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=31536000`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/_next/static/css/4b83d2c75330f0e20ee0.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=31536000`
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``

Instances: 10

### Solution

Validate that the response does not contain sensitive, personal or user-specific information.  If it does, consider the use of the following HTTP response headers, to limit, or prevent the content being stored and retrieved from the cache by another user:
Cache-Control: no-cache, no-store, must-revalidate, private
Pragma: no-cache
Expires: 0
This configuration directs both HTTP 1.0 and HTTP 1.1 compliant caching servers to not store the response, and to not retrieve the response (without validation) from the cache, in response to a similar request. 

### Reference


* [ https://tools.ietf.org/html/rfc7234 ](https://tools.ietf.org/html/rfc7234)
* [ https://tools.ietf.org/html/rfc7231 ](https://tools.ietf.org/html/rfc7231)
* [ http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html (obsoleted by rfc7234) ](http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html (obsoleted by rfc7234))


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ Storable but Non-Cacheable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are storable by caching components such as proxy servers, but will not be retrieved directly from the cache, without validating the request upstream, in response to similar requests from other users. 

* URL: https://realm-registry.apps.silver.devops.gov.bc.ca/bcid-favicon-32x32.png
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`

Instances: 1

### Solution



### Reference


* [ https://tools.ietf.org/html/rfc7234 ](https://tools.ietf.org/html/rfc7234)
* [ https://tools.ietf.org/html/rfc7231 ](https://tools.ietf.org/html/rfc7231)
* [ http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html (obsoleted by rfc7234) ](http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html (obsoleted by rfc7234))


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3


