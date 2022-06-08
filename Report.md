# Broken Access Control

## Flaw: Admin page can be accessed by anyone by appending `/admin` to the domain even if user isn't admin (Brief)
### Flaw Description
If a user's `role` column is `admin` in the MySQL `users` database, the top navigation bar will show an "Admin" button. This button will bring the admin user to http://domain/admin page.

The /admin page shouldn't be accessible by default unless logged in with an account with the `admin` role. However with Broken Access Control, the /admin page is visible to anyone with no difference in information visibility.

This means that the /admin page doesn't have a check for logged in sessionID and users with `admin` role. 

This can be done via authentication and then checking the CSRF, cookies or headers for existing authenticated token/ticket.

This is a common attack against broken access control, as shown in PurpleBox's post regarding Broken Access Control, where this flaw is described as "access to admin pages where sensitive functions take place generally results in vertical privilege escalation", and "attackers usually perform brute-force attacks to discover hidden, sensitive pages like admin pages" (PurpleBox, 2021).
    
## Flaw: `/api/users/[user ID]` HTTP PUT endpoint doesn't check user authentication, any crafted HTTP PUT request will be accepted (Detailed)
### Flaw Description
When a user goes to the /profile page when signed in, they can cmodify their account details, like name, username, email, and password.

However, the HTTP PUT request has a few flaws.

Firstly, the user whose details should be updated is determined by the `id` column in the MySQL users database, and is appended behind `/api/users/`. For example, if "weiliang" username has an `id` of 1, the PUT request will be sent to `/api/users/1`.

Secondly, there is no cookies, headers or CSRF as a second check on whether the HTTP PUT request originated from the user who is firstly signed in, and secondly is the same user who is requesting the PUT request.

Combining both flaws together makes for a very dangerous and glaring vulnerability. This allows anyone who is able to get a sample of this PUT request to craft their own PUT request, without being authenticated on the website. They can then alter any existing user ID's details to their own details to store in the MySQL database. This can compromise an existing user's ability to use the service using their account, or if registration is not allowed, an attacker can take over an account without creating a new one. At worst, they could inject stored XSS or SQL injection to execute arbitary code, leading to an exploit chain.

This vulnerability is known as "Insecure Direct Object Reference", and "usually occurs when different parts of a web application can be accessed through changing user inputs, such as a parameter inside a URL" (Bruce K., 2021).

![Figure 1.1: Explaining vulnerabilities in HTTP PUT request](Screenshots/BrokenAccessControl/UpdatingUserInfo/Explain.png)

### Example
In this example, we already can access the backend `users` MySQL database, so we will use the given data to login to a `member` role user, then privilege escalate the `member` user to an `admin` role user.

The regular user will be "brenda" with user ID 2, and the admin user will be "weiliang" with user ID 1.

We will use BurpSuite to intercept the HTTP request.

1. We will first obtain a HTTP PUT request from the profile update page from "brenda". We will request it with the new password we intend for "weiliang".

![Figure 1.2: Original HTTP PUT request & Original MySQL users database data](./Screenshots/BrokenAccessControl/UpdatingUserInfo/1ObtainRequest.png)

2. We will then change the HTTP PUT request's API endpoint address from src_html{/api/users/2} to src_html{/api/users/1}. We will also change the request body data for username, first name, last name, and email, from "brenda"'s details to random details. It doesn't matter if the request body's details match the database's current details for that user ID, thus we can put in random data and the request will still be allowed and processed.

![Figure 1.3: Altered HTTP PUT request & new user ID 1's data reflected in MySQL](./Screenshots/BrokenAccessControl/UpdatingUserInfo/2RogueRequest.png)

3. As shown in Figure 1.3, we have now changed the username and password for weiliang.

![Figure 1.4: Logged in using new credentials](./Screenshots/BrokenAccessControl/UpdatingUserInfo/3LoggedIn.png)

4. As shown in Figure 1.4, we are now able to login with the new username and password, and since we are admin, we now see the Admin button in the navbar.
 
## Recommendation
"Except for public resources, deny by default" and "implement access control mechanisms once and re-use them throughout the application". (OWASP, 2021)

The website should enforce HTTP endpoints access control using the user authentication and roles already implemented into the web application. 

Currently, the user authentication only changes the user's access control in terms of the webpage content, but not the HTTP endpoints.

By denying by default at the HTTP endpoint level, and only allowing access based by checking a user's name and any accompanying identification info (user ID, role etc), and then checking once more with the backend SQL `users` database that the user's accompanying identification info matches, we can mitigate the 2 vulnerabilities.

## Code to Resolve Flaw
In ./middlewares/jwt.js file:
``` javascript
const jwt = require('jsonwebtoken');
const config = require('../config');

var verifyFn = {
  verifyToken: function(req, res, next) {
    var token = req.headers['authorization'];

    res.type('json');
    if (!token || !token.includes("Bearer ")) {
      console.log("not bearer token");
      res.status(403);
      res.send(`{"Message":"Not Authorized"}`);
    } else {
      token = token.split('Bearer ')[1];
      token = token.substring(7);
      jwt.verify(token, config.jwt, function(err, decoded) {
        if (err) {
          console.log("token invalid");
          res.status(403);
          res.send(`{"Message":"Not Authorized"}`);
        } else {
          req.username = decoded.username;
          req.role = decoded.role;
          next();
        }
      });
    }
  },

  verifyAdmin: function(req, res, next) {
    res.type('json');
    if (req.type != "admin") {
      res.status(403);
      res.send(`{"Message":"Not Authorized"}`);
    } else {
      next();
    }
  },

  verifyUserID: function(givenId, req, res, next) {
    res.type('json');
    if (req.id != givenId) {
      res.status(403);
      res.send(`{"Message":"Not Authorized"}`);
    }
  }
}

module.exports = verifyFn;
```

To add admin role verification, add the following to the `router.get('/admin')` endpoint in the ./controller/views.js file:
``` javascript
router.get('/admin', jwt.verifyToken, jwt.verifyAdmin, (req, res) => {
...
```

To add user ID verification to the PUT endpoint, add the following to the `router.put('/:id')` endpoint in the ./controller/users.js file:
``` javascript
router.put('/:id', bruteforce.prevent, jwt.verifyToken, jwt.verifyUserID, validation.validateUser, contentChecker([ 'username', 'password', 'firstname', 'lastname', 'email' ]), (req, res) => {
...
```

# Cryptographic Failures

## Flaw: No data is encrypted at rest in MySQL database (Brief)
### Flaw Description
No data is encrypted at rest when it is stored in the MySQL database.

While not all the data needs to be encrypted, like product information, sensitive data such as names, usernames, emails, and especially passwords, should be encrypted.

"Encryption scrambles your password so it's unreadable and/or unusable by hackers. That simple step protects your password while it's sitting in a server, and it offers more protection as your password zooms across the internet." (Okta, 2022)

Without encryption at rest of sensitive data such as passwords, the following scenario could happen: "If a hacker gets inside" your backend servers, "what happens next? All of your efforts go to waste, and your username and password are sold on the open market to the highest bidder." (Okta, 2022)

## Recommendation
Passwords should be encrypted at rest, at the very least.

"A more secure way to store a password is to transform it into data that cannot be converted back to the original password. This mechanism is known as hashing." (Auth0, 2019)

Auth0 recommends using "the industry-grade and battle-tested bcrypt algorithm to securely hash and salt passwords" (Auth0, 2021).

## Code to Resolve Flaw
In ./model/users.js file, change the insert and update function to look like this:
``` javascript
    insert: function (user, callback) {
        let conn = database.getConnection();
        conn.connect((err) => {
            if (err) return callback(err, null);
            bcrypt.hash(user.password, 10, function(err, hash) {if (err) return callback(err, null); // added bcrypt hashing of password
                        let sql = `INSERT INTO users (username, password, firstname, lastname, email) VALUES (?, ?, ?, ?, ?)`;
                        console.log(sql);
                        let params = [user.username, hash, user.firstname, user.lastname, user.email];
                        conn.query(sql, params, (err, results) => {
                            conn.end();
                            if (err) return callback(err, null);
                            callback(null, { id: results.insertId });
                        });});});},
    update: function (user, callback) {
        let conn = database.getConnection();
        conn.connect((err) => {
            if (err) return callback(err, null);
            bcrypt.hash(user.password, 10, function(err, hash) {if (err) return callback(err, null); // added bcrypt hashing of password
            let sql = `UPDATE users SET username = ?, password = ?, firstname = ?, lastname = ?, email = ? WHERE id = ?`;
            console.log(sql);
            let params = [user.username, hash, user.firstname, user.lastname, user.email, user.id];
            for (let param of params) {
                sql = sql.replace('?', `"${param}"`);
            }
            conn.query(sql, (err, results) => {
                conn.end();
                if (err) return callback(err, null);
                if (results.affectedRows < 1) return callback(null, null);
                callback(null, { id: user.id });
            });});});},
```

## Flaw: Data sent from client side is not encrypted in transit (Detailed)
### Flaw Description
All data sent during transit, or in the HTTP requests, is unencrypted. An example would be the HTTP PUT updated user details data shown in the `/api/users/[user ID]` flaw.

This means that sensitive information such as names, usernames, emails, and especially passwords, is sent in cleartext. This makes it easy for packet sniffers or the like to view the data. For example, "if sensitive information in sent over the internet without communications security, then an attacker on a shared wireless connection could see and steal another user’s data" (OWASP, 2018)

### Recommendation
Use HTTPS, which encrypts HTTP traffic with TLS.

"TLS is by far the most common and widely supported cryptographic protocol for communications security. It is used by many types of applications (web, webservice, mobile) to communicate over a network in a secure fashion." (OWASP, 2018)

### Code to Resolve Flaw
Code was taken from NodeJS's official "How to create an https server" guide.

In a Linux Bash shell (or Cygwin/Git Bash on Windows), generate a new SSL certificate:

``` shell
openssl genrsa -out key.pem
openssl req -new -key key.pem -out csr.pem
openssl x509 -req -days 9999 -in csr.pem -signkey key.pem -out cert.pem
rm csr.pem
```

On the NodeJS side, modify bin/runner.js to use the following code:

``` javascript
const app = require('../app');
const https = require('https');
const fs = require('fs');
const httpsOptions = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem')
};

let port = process.env.PORT || 3000;

https.createServer(httpsOptions,app).listen(port, () => console.log(`Server listening on port ${port}`));
```

![Figure 3.1: Implementing HTTPS](Screenshots/Crypto/TLS/1ImplementHTTPS.png)

(NodeJS, 2011)

Instead of listening directly on the app.js code, we will set the listen on the HTTPS server, and run the app within the HTTPS server.

Alternatively, a reverse proxy exposed to the Internet that serves HTTPS TLS for the Node web server running in the same internal network as the reverse proxy is another way to implement HTTPS TLS without modifying any code. However, if an attacker gains access to the internal network, they will be able to see the HTTP cleartext traffic using a packet sniffer run on the internal network.

Running a WireShark before HTTPS, we will be able to see the unencrypted HTTP traffic, but after HTTPS, all we can see is TLSv1.2 traffic.

### Example
In this example, I (Jia Jian) have set up the website behind my network's reverse proxy which also serves HTTPS on the standard TCP port 443. This reverse proxy runs on 10.0.0.11. My Node web server also exposes HTTP on port 30001 on the same 10.0.0.11 machine. My SSL certificate is a wildcard certificate from Let's Encrypt, a trusted CA, for my domain "jjgadgets.tech", thus I configured my reverse proxy to serve HTTPS for requests going to "https://sc.jjgadgets.tech". Creating a certificate using the above code snippet will create a certificate that does not normally originate from a system trusted CA.

Before implementing HTTPS, let's view the HTTP cleartext traffic of a login POST request in WireShark, while showing that the browser is using HTTP. In my case, the destination will be http://10.0.0.11:30001.

![Figure 2.2: WireShark HTTP cleartext packets](Screenshots/Crypto/TLS/2NoHTTPSwireshark.png)

Now, switching over to the same web server but with HTTPS, there is now no sight of the HTTP traffic, only the TLSv1.2 traffic which shows "http-over-tls".

![Figure 2.3: WireShark TLSv1.2 HTTPS packets](Screenshots/Crypto/TLS/3HTTPSnoWireShark.png)

# Cross Site Scripting or XSS

## Flaw: `/search` page is vulnerable to Basic Reflected XSS (Brief)
### Flaw Description
In the /search page and the search popup that shows when a user presses the search button, the query is vulnerable to basic reflected XSS.

Basic XSS refers to any user being able to type in basic <script> HTML tag based JavaScript code and execute unwanted arbitary code, which is known as Cross Site Scripting, or XSS.

An example of such JavaScript code is:
``` html
<script>alert("test")</script>
```

A reflected XSS is "non-persistent", and "allows the attacker to inject malicious content into one specific request". This means that to compromise a specific user, that user account has to be the one "opening a malicious URL or submitting a specially crafted POST form that contains the payload" (NetSparker, 2021).

## Flaw: `/feedback` page is vulnerable to Basic Stored XSS (Detailed)
### Flaw Description
In the /feedback page, a user may submit a feedback form that contains basic XSS JavaScript code, and the code will be stored into the `comments` MySQL database.

When any user then loads the /feedback page, the code is loaded into the browser, and then executed on the browser.

This is "very dangerous because the payload is not visible to any client-side XSS filters and the attack can affect multiple users without any further action by the attacker" (NetSparker, 2021)

The code used is the same as above.

### Example
In this example, we will store a simple script into the `comments` MySQL database that will show an alert when the browser loads.

``` html
<script>alert("GET HAXXORD MWAHAHA!!")</script>
```

1. We will first type the script into the /feedback page and submit it to store it in the database.

![Figure 3.1: Storing XSS code in database](./Screenshots/XSS/Stored/1InputCode.png)

2. We will then refresh the browser on the /feedback page to load the `comments` database data, thus loading the JavaScript `<script>` code.

![Figure 3.2: XSS code loads in browser](./Screenshots/XSS/Stored/2CodeRuns.png)
    
## Recommendation
The website should have user input validation and encoding in place. User input validation is a "defense technique used on the server-side to prevent XSS attacks", and "is performed to make sure only secure data enters an information system" (Pauline M., 2021). To ensure best effectiveness, user input validation should occur on the server side "as soon as data is received from the other party" (Pauline M., 2021). Validating user input on the client side is not as effective as server side, as a user may simply disable execution of the script and the code will still be able to run.

## Code to Resolve Flaw
Add a function to ./middlewares/validation.js called "sanitizeResult":

``` javascript

var validator = require('validator');

var validation = {
    ...
    sanitizeResult: function(result) {
        for (i = 0; i < result.length; i++) {
        var row = result[i];
        console.log(row);
            for (var key in row) {
                val = row[key];
                if (typeof val === "string") {
                    row[key] = validator.escape(val);
                }
            }
        }
    }
    ...
    }
```

Add `const validation = require('../middlewares/validation.js')` to all controller files.

Add `validation.sanitizeResult(result)` above all lines with `res.send(result)`, and add `validation.sanitizeResult(results)` above all lines with `res.send(results)`, using the following `sed` commands in a Bash shell:

``` shell
sed -i '/send(result)/i \
  validation.sanitizeResult(result);' ./web/controllers/*
sed -i '/send(results)/i \
  validation.sanitizeResult(results);' ./web/controllers/*
```

# Identification or Authentication Failures

## Flaw: Permits brute force or other automated attacks (Brief)
### Flaw Description
The website does not have any browser timeout or account lockout in the event that a single browser client makes more than a predefined number of login requests.

Lack of account or browser lockout can result in brute force attacks. A brute force attack is when an attacker tries to gain access to an account by "systematically trying every possible combination of letters, numbers, and symbols" (Esheridan, 2020) until a combination matches with the password stored in the authentication database. Since a brute force attack usually requires a large number of password attempts, "an attacker can always discover a password through a brute-force attack" (Esheridan, 2020). Without any protection against brute force attacks, it is very likely that an attacker will attempt this basic "common threat" (Esheridan, 2020).

### Recommendation
An easy way to implement protection against brute force attacks is to "simply lock out accounts after a defined number of incorrect password attempts" (Esheridan, 2020). As long as there is a counter on how many attempts an account has tried logging in without success, we can lock a user out after an attempt threshold has been breached. The lockout's duration "can last a specific duration, such as one hour, or the accounts could remain locked until manually unlocked by an administrator" (Esheridan, 2020).

Another alternative would be to host the webpage behind CloudFlare DNS to utilize CloudFlare's Rate Limiter, which is designed to prevent brute forcing. However, if the page is not accessed through the domain being resolved through CloudFlare, the webpage will still be vulnerable to brute forcing, thus firewall rules should also be set to only allow CloudFlare's proxy IPs as the source for incoming packets to the web server.

### Code to Resolve Flaw
In every controller, add the following to the top to initialize the brute-force prevention:

``` javascript
const ExpressBrute = require('express-brute');

var bfStore = new ExpressBrute.MemoryStore();
var bruteforce = new ExpressBrute(bfStore);
```

In each of the HTTP endpoints, add `bruteforce.prevent()` in between the endpoint address, and any functions to be run after the HTTP endpoint receives the HTTP request. The brute force protection should be applied before any input validation, as it should be the first line of defence.

``` javascript
...
router.get('/', bruteforce.prevent, (req, res) => {
...
router.get('/:id', bruteforce.prevent, (req, res) => {
...
router.post('/', bruteforce.prevent, validation.validateUser, contentChecker([ 'username', 'password', 'firstname', 'lastname', 'email' ]), (req, res) => {
...
router.put('/:id', bruteforce.prevent, validation.validateUser, contentChecker([ 'username', 'password', 'firstname', 'lastname', 'email' ]), (req, res) => {
...
```

## Flaw: No password requirement policy (Detailed)
### Flaw Description
The website does not have a strict password requirements policy, such as numbers are required, symbols are required, what length must the password minimally be, and more.

"Authentication mechanisms often rely on a memorized secret (also known as a password) to provide an assertion of identity for a user of a system." (Mitre, 2006) The integrity of an account, or even the backend systems if other vulnerabilities are found and used, may be easily compromised if an attacker can easily guess weak passwords with short lengths via brute forcing, passwords that do not have numbers to extend the range of characters to test for, and more.

Weak passwords also make for higher likelihood of brute forcing than longer passwords. According to Microsoft's "Head of Deception" security, Ross Bevington, "77% of the passwords" involved in brute force attacks on Microsoft honeypots "were between 1 and 7 characters long" (MalwareBytes, 2021). This is most likely due to the exponential increase in the possible combinations as the number of characters increase. Since "only 6% of the passwords were longer than 10 characters" (MalwareBytes, 2021), that makes for a good starting point in minimum password length in password policies.

### Example
We will create a user account with username and all other fields as "test2", and we will use a weak password "password". We will also use "emailyay" for the email to show that the email field doesn't have input validation either.

![Figure 4.1](Screenshots/AuthFailure/PermitsWeak/1AddWeakPassword.png)

As shown in Figure 4.2, the website will let you register the password without checking any password policies, and the email without checking if the email given is a valid email address format.

![Figure 4.2](Screenshots/AuthFailure/PermitsWeak/2RegisterYes.png)

This shows that there is no input validation for the whole registration page.

### Recommendation
In general, password requirements should be implemented and enforced when a user sets or changes their passwords. Some general recommendations from CWE-521 include, but is not limited to: "enforcement of a minimum and maximum length", "restrictions against password reuse", "restrictions against using common passwords", and "restrictions against using contextual strings in the password (e.g., user id, app name)" (Mitre, 2006). As stated above, a good starting point for minimum password length is 10.

### Code to Resolve Flaw
Add a function to ./middlewares/validation.js called "validateUser":

``` javascript
var validator = require('validator');

var validation = {
    ...
     validateUser: function(req, res, next) {
        var email = req.body.email;
        var password = req.body.password;

        if (validator.isEmail(email) && validator.isStrongPassword(password)) {
            next();
        } else {
            logger.error("Password ${password} and/or Email ${email} not valid!");
            return res.status(500).send({ message: 'Password ${password} and/or Email ${email} not valid!' });
        }
    },
   ...
    }
```

Add `const validation = require('../middlewares/validation.js')` to all controller files.

To all POST and PUT HTTP endpoints dealing with passwords, in this case `router.post('/',` and `router.put('/',`, add `validation.validateUser` between the endpoint and any functions behind the endpoint.

``` javascript
...
router.post('/', validation.validateUser, contentChecker([ 'username', 'password', 'firstname', 'lastname', 'email' ]), (req, res) => {
...
router.put('/:id', validation.validateUser, contentChecker([ 'username', 'password', 'firstname', 'lastname', 'email' ]), (req, res) => {
...
```

# Security Logging and Monitoring Failures

## Flaw: Errors are not logged (Brief)
### Flaw Description
No errors such as MySQL connection errors, MySQL query errors, login errors, are logged. 

Similar to user activity not being logged, OWASP states "warnings and errors generate no, inadequate, or unclear log messages" as a failure of security logging and monitoring. 

Logging errors is important as errors could be signs of malicious activity, for example error logs could be used to "identify suspicious or malicious accounts and held for enough time to allow delayed forensic analysis." (OWASP, 2021)

## Flaw: HTTP endpoint activity is not logged (Detailed)
### Flaw Description
The website server does not log to either console or a file of what files are being accessed by who, and what the status is.

This is dangerous as there is no traces of what a particular user has accessed, leading to lack of evidence and tracing of malicious activity.

For example, if an attacker runs a PUT or POST on a vulnerable site, with no access logs, it becomes difficult to trace back when exactly said attacker ran the PUT/POST requests, and from what IP, and whether it was successful or not.

Logging user activity helps "detect, escalate, and respond to active breaches. Without logging and monitoring, breaches cannot be detected". In this case, "Logs of applications and APIs are not monitored for suspicious activity".  (OWASP, 2021)

### Example
We will use reflected XSS as an example, since the search function in this web app appends the search query into the HTTP link, with the syntax: `http://domain/search/[query]` which allows us to see the malicious request easily using Morgan which logs HTTP requests.

Without any logging, we would not have been able to see or know that an attacker had sent a malicious reflected XSS HTTP request to the server.

![Figure 5.1](Screenshots/Logging/UserActivity/1NoLogXSS.png)

If we add Morgan to `app.js`, we are now able to see the HTTP request, and would be able to trace back the malicious request if it's stored in a file.

![Figure 5.2](Screenshots/Logging/UserActivity/2LogXSS.png)

## Recommendation
Implement logging that can log to files.

In NodeJS, there are 2 packages that can easily achieve this. Since our application "communicates via HTTP, you'll want some kind of middleware to monitor incoming requests. Morgan is a request logger that does just that." (HeyNode, 2020)

After being able to log the data, there needs to be "some kind of way to persist that data to view at a later time. For this example we'll be using Winston." (HeyNode, 2020)

## Code to Resolve Flaw
We will use 2 popular NodeJS logging utilities to log user activity and errors, Morgan and Winston.
Installing `morgan` and `winston`: 

``` shell
npm install morgan && npm install winston
```
In `./app.js`, implement `winston` to initialize a logger that logs any message passed to it to a file, and `morgan` to log all HTTP requests to `winston`'s initialized `logger` logger. Place between `const app = express();` and `app.use(express.urlencoded({ extended: true }));` lines:

``` javascript
...
const app = express();

// import Node logging modules Winston and Morgan
const morgan = require('morgan');
const winston = require('winston');

// init new Winston logger listener
const logger = new winston.createLogger({
  level: 'debug',
  transports: [
    new winston.transports.File({ filename: './logs.log', level: 'debug' }),
    new winston.transports.Console({ level: 'debug', handleExceptions: true, json: false, colorize: true })
  ],
  exitOnError: false
});

// define stream logger for Morgan to use
logger.stream = {
  write: function(message, encoding) {
    logger.info(message);
  },
};

// init Morgan logger to stream write to Winston's initialized logger
app.use(morgan("common", { stream: logger.stream }));

app.use(function(err, req, res, next) {
  logger.error(`${req.method} - ${err.message}  - ${req.originalUrl} - ${req.ip}`);
  next(err)});

// Content parsing
app.use(express.urlencoded({ extended: true }));
...
```

Adding `logger.[level]("[message]")` (replacing [level] with appropriate log priority level, and [message] with the actual content of the log message) to any messages that are to be logged, such as errors or failures on the authentication endpoints, will allow them to be centrally logged to Winston's configured logging transports, in this case the console and the file `./logs.log`.

Adding `app.use(function(err, req, res, next) {logger.error(`${req.method} - ${err.message}  - ${req.originalUrl} - ${req.ip}`); next(err)});` at the top of a function will allow all errors to be logged to Winston.

# Testing Tools and Methods
### Docker
We used Docker to deploy the website stack. The website code runs in an official NodeJS Docker container, the database uses the latest official MySQL Docker container, and Adminer is the MySQL frontend of choice.
### Adminer
We used Adminer instead of MySQL Workbench to inspect the database, as it has an interface that is easier to navigate, and it is runs off a single PHP file. This means that it can be used in a browser, while remaining fast and lightweight. This allows us to work on this project on the go from a mobile phone or tablet.
### BurpSuite
Burpsuite was used to intercept HTTP and HTTPS requests. This is allows us to view data in transit. Such examples include, but are not limited to: request body, parameters, cookies, headers, CSRF, and the HTTP endpoint the request is being sent to.
### WireShark
WireShark was used to compare the difference between HTTP and HTTPS (TLS) packets, where HTTP request data can be viewed in packet sniffers in plaintext, while HTTPS traffic will only show up as encrypted TLS packets.
### Git Workflow
We used the Git workflow to do this project, as it provides a very easy way to collaborate with code. Unlike Microsoft or Google collaboration tools, which only works for documents, using a Git provider such as GitHub opens up more possibilities, such as version control for code, being able to write this report in Markdown which is allows easier formatting for code than Word, and the ability to use CI/CD to push a change to a live server that will then run a specified set of commands, in this case redeploying the Node web server.

# References (just add name and link first, will change in Word on Sunday)
Esheridan, 2020: https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks
MalwareBytes, 2021: https://blog.malwarebytes.com/reports/2021/11/password-usage-analysis-of-brute-force-attacks-on-honeypot-servers/
Pauline Mwangi, 2021: https://www.section.io/engineering-education/how-to-prevent-cross-site-scripting-in-node-js/
PurpleBox, 2021: https://www.prplbx.com/resources/blog/broken-access-control/#61-access-to-admin-pages
Mitre, 2006: https://cwe.mitre.org/data/definitions/521.html
Bruce Kang, 2021: https://www.synack.com/blog/preventing-broken-access-control-the-no-1-vulnerability-in-the-owasp-top-10-2021/
OWASP, 2018: https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere
NodeJS, 2011: https://nodejs.org/en/knowledge/HTTP/servers/how-to-create-a-HTTPS-server/
Okta, 2022: https://www.okta.com/identity-101/password-encryption/
NetSparker, 2021: https://www.netsparker.com/blog/web-security/cross-site-scripting-xss/
OWASP, 2021: https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/
OWASP, 2021: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
Auth0, 2019: https://auth0.com/blog/hashing-passwords-one-way-road-to-security/
Auth0, 2021: https://auth0.com/blog/hashing-in-action-understanding-bcrypt/
HeyNode, 2020: https://heynode.com/blog/2020-05/add-server-logs-your-nodejs-app-morgan-and-winston/
