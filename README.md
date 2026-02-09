Excellent work — you’ve successfully completed the DVWA setup and testing on Kali Linux, and your screenshots clearly show:

* Apache & MariaDB running
* DVWA login page working
* Database setup completed
* DVWA dashboard accessible
* Minor PHP warning (db_port) identified and fixed

Below is a FINAL, SUBMISSION-READY Vulnerability Assessment Report and a README.md that you can directly copy into your GitHub repository.



 📄 FINAL VULNERABILITY ASSESSMENT REPORT

Task 7: Web Application Vulnerability Testing



 1. Introduction

This task focuses on identifying common web application vulnerabilities using a deliberately vulnerable application. The objective is to understand how vulnerabilities such as SQL Injection and Cross-Site Scripting (XSS) occur, how attackers exploit them, and how they can be mitigated.

The testing was performed on **Damn Vulnerable Web Application (DVWA)** using **Kali Linux**.



 2. Environment Setup

 Operating System

 Kali Linux (latest)

 Web Application

Damn Vulnerable Web Application (DVWA)

 Tools Used

 Apache2
 MariaDB (MySQL)
 PHP 8.x
 Burp Suite Community Edition (optional for interception)



 3. DVWA Installation & Configuration

Steps Performed

1. Installed Apache, MariaDB, PHP, and required extensions.
2. Cloned DVWA into /var/www/html/.
3. Configured config.inc.php with database credentials.
4. Created database and user (dvwa) in MariaDB.
5. Enabled required PHP settings and extensions.
6. Restarted Apache service.
7. Accessed DVWA via browser.
8. Set DVWA security level to **Low**.

 Configuration Fixes

* Resolved MySQL authentication error by recreating database user.
* Fixed PHP warning by adding:

php
  $_DVWA['db_port'] = '3306';

 4. Vulnerability Testing

4.1 SQL Injection

Vulnerability Name: SQL Injection
Affected Module: SQL Injection
Security Level: Low

Payload Used:


1' OR '1'='1


Observation:

* Application returned all database records.
* Authentication and query logic were bypassed.

Impact:

* Unauthorized data access
* Potential data leakage or manipulation

Severity: High

<img width="642" height="591" alt="image" src="https://github.com/user-attachments/assets/8bb32dec-53bb-4468-acd8-06520558de68" />
<img width="642" height="591" alt="image" src="https://github.com/user-attachments/assets/c70da08e-6745-4f66-ac24-8ccb8bf85ca9" />
<img width="1117" height="735" alt="image" src="https://github.com/user-attachments/assets/6d582c5a-f56b-4ad6-831e-eec6177f1640" />
<img width="1524" height="779" alt="image" src="https://github.com/user-attachments/assets/11fe3c18-ce51-481a-9c06-3f08abfc017c" />



 4.2 Cross-Site Scripting (XSS)

Vulnerability Name: Reflected XSS
Affected Module: XSS (Reflected)
Security Level: Low

Payload Used:

html
<script>alert('XSS')</script>


Observation:

JavaScript executed in the browser.
 Alert popup confirmed successful XSS.

Impact:

 Session hijacking
 Credential theft
 Malicious script execution

Severity: Medium


 5. Application Response Analysis

* DVWA accepted unsanitized user input.
* No input validation or output encoding was applied.
* Errors and warnings were displayed due to insecure PHP configuration.
* Application behaved as expected for a deliberately vulnerable environment.

 6. Mitigation Recommendations

 SQL Injection Prevention

 Use prepared statements and parameterized queries.
 Implement input validation.
 Apply least privilege principle for database users.

 XSS Prevention

 Sanitize and encode user input/output.
 Implement Content Security Policy (CSP).
 Avoid rendering raw user input in HTML.

 7. Final Outcome

 Successfully deployed DVWA on Kali Linux.
 Identified and exploited SQL Injection and XSS vulnerabilities.
 Understood practical exploitation techniques.
 Learned mitigation strategies for common web vulnerabilities.

 8. Conclusion

This task enhanced practical knowledge of web application security testing and provided hands-on experience with real-world vulnerabilities in a controlled environment.




markdown
  – Web Application Vulnerability Testing

 Overview
This repository contains the implementation and findings of Task 7: Web Application Vulnerability Testing as part of a Cyber Security Internship.

The objective was to set up a vulnerable web application and identify common vulnerabilities using ethical hacking techniques.

 Environment
- OS: Kali Linux
- Web Server: Apache2
- Database: MariaDB (MySQL)
- Language: PHP
- Vulnerable App: DVWA (Damn Vulnerable Web Application)

 Tools Used
- DVWA
- Burp Suite Community Edition
- Apache2
- MariaDB
- PHP

 Vulnerabilities Tested
- SQL Injection
- Cross-Site Scripting (XSS)


 Key Findings
- SQL Injection allowed unauthorized access to database records.
- XSS allowed execution of malicious JavaScript in the browser.
- Application lacked proper input validation and output encoding.



 Repository Structure


DVWA-Task-7/
│
├── screenshots/
│   ├── dvwa_login.png
│   ├── setup_success.png
│   ├── sql_injection.png
│   └── xss_alert.png
│
├── report/
│   └── vulnerability_assessment_report.pdf
│
└── README.md

Learning Outcome
- Practical understanding of OWASP Top 10 vulnerabilities
- Hands-on experience with web application testing
- Familiarity with DVWA and Kali Linux tools

<img width="642" height="591" alt="image" src="https://github.com/user-attachments/assets/236e14a2-a8a4-4ee2-a96d-ad79d1599fd6" />






 Burp Suite Testing (HTTP Interception & Manipulation)

Tool Used

Burp Suite Community Edition
Platform: Kali Linux

 Objective

To intercept, analyze, and manipulate HTTP requests sent between the client (browser) and the DVWA server in order to identify and exploit web application vulnerabilities.

 Burp Suite Configuration

1. Burp Suite Community Edition was launched from Kali Linux.
2. Proxy listener was enabled on:

  
   127.0.0.1 : 8080

3. Browser proxy settings were configured to route traffic through Burp.
4. Burp Proxy Intercept mode was turned ON.



 Request Interception

* User interactions such as login attempts and form submissions were captured.
* HTTP requests and responses were observed in real time.
* Parameters were identified and modified directly within Burp.

📸 *Screenshot: Burp Suite intercepting DVWA HTTP request*
<img width="1524" height="824" alt="image" src="https://github.com/user-attachments/assets/0f75f41b-dc05-42e3-ad33-ac99796a9ea1" />



 SQL Injection Testing via Burp

* Login request was intercepted.
* Username and password parameters were modified.

Injected Payload:


admin' OR '1'='1 

Observation:

* Server accepted manipulated request.
* Authentication logic was bypassed.
* SQL Injection vulnerability confirmed.

Impact:

* Unauthorized access to application
* Possible database compromise


 XSS Testing via Burp

* Reflected XSS request was intercepted.
* Malicious JavaScript payload injected into request parameter.

Payload Used:

html
<script>alert('XSS')</script>

Observation:

* JavaScript executed in browser.
* Alert popup confirmed reflected XSS vulnerability.



 Security Impact

* Burp Suite demonstrated how attackers can manipulate client-side requests.
* Lack of server-side validation enabled exploitation.
* Reinforces the importance of secure coding practices.


 Conclusion (Burp Testing)

Burp Suite proved effective in identifying and exploiting vulnerabilities by intercepting and modifying HTTP traffic. This highlights how attackers can bypass front-end restrictions and directly target backend logic.


🔹 ADD THIS SECTION TO YOUR README.md

Paste this below “Vulnerabilities Tested”:

markdown
 Burp Suite Testing

Burp Suite Community Edition was used to intercept and analyze HTTP requests between the browser and DVWA.

Activities Performed
- Intercepted login and form submission requests
- Modified request parameters in real time
- Tested SQL Injection and XSS via intercepted traffic

 Key Observations
- SQL Injection payloads successfully bypassed authentication
- XSS payloads executed malicious JavaScript
- Application lacked server-side input validation

Burp Suite demonstrated how attackers can manipulate HTTP requests to exploit vulnerabilities.





