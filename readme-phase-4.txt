###		Ethical and Legal Considerations:

	From testing the app i learned that cybersecurity work is not only technical but it also requires ethical judgment and good understnding of privacy laws. I made sure that all my security testing was done only on my own local system to follow an important ethical rule that security testing must always happen in an authorized and controled environment. Practicing this helped me think a bit more like a security professional who respects boundaries and undestands responsibilities, as professionals must act honestly. I learned that hiding vulnerabilities, leaking data, or testing without consent could violate both ethical standards and Canadian privacy laws. In this project I tried to follow these principles by encrypting user data, validating inputs, preventing unsafe actions, and fixing vulnerabilities without exposing any private information. i also thought about how user data must be handled carefully under privacy laws, to be collected for a clear purpose, stored securely, and never shared without users consent. The biggest lesson I learned is that good security is not just about protecting systems—it’s also about protecting people at every step with good ethical and legal considerations.

Part E:

###		Secutiry Testing:

	Manual Testing: 
	
		Begin by checking for SQL injection risks in authentication forms. In the login and signup routes enter SQLstyle payloads in the username and password fields such as values with quotes or patterns like OR 1=1 to see if the applicaton allows unauthorized acess or behaves unexpectedly. The expected result is that all invalid inputs are rejected and no errors or bypasses occur.

		Next we will test for XSS vulnerabilities in any user input fields that are stored or displayed back to the user such as the name, email, and bio fields in the profile form. Enter payloads like <script>alert("XSS")</script>, various HTML tags, or image tags with event handlers, and then save and reload the dashboard page. Confirm that the script does not execute, that tags are removed, and that the output appears only as plain text.

		After manual tests run npm audit in the project directory to scan all installed dependencies for known vulnerabilities. Review the results while paying attention to the severity level.

	Automated scan using OWASP ZAP: 

		Configure ZAP to target https://localhost:3443 and run the automated attack/scan. Review the list of alerts it produces. After applying fixes in the code, re run ZAP with the same targwt to verify whether the number and severity of alerts have decreased and to confirm that some issues were successfully mitigated

###		Vulnerability Fixes:
	
	Based on the results of manual testing, npm audit, and ZAP scans, several changes were made to improve security. The Content Security Policy was tightened using Helmet. A noCache middleware was added and applied to sensitive routes like /dashboard, /me, and authentication to prevent caching of private data. The Express middleware order was adjusted so Helmet runs before static file serving, ensuring all responses receive CSP and other security headers. These fixes were validated by checking the response headers in the browser’s developer tools and by rerunning ZAP scans to confirm that some previous alerts were removed or downgraded.

###		Testing Tools:

	I used several tools for the security testing. I used Postman to send HTTP requests to various API endpoints (login, signup, profile, token refresh) and to inspect responses, error messages, and cookies. I used browser developer tools to see headers, cookies, CSP values, and cache control. The npm audit command was used to scan dependencies for known security vulnerabilities. OWASP ZAP served as main auto scanner, crawling the application, inspecting HTTP traffic, and reporting vulnerabilities.

###		Lessons Learned: 

	The security process showed me that protecting a web application requires code changes and regular testing. It also became clear that some findings, especially related to CSP, can be challenging to fully resolve. applying fixes in small steps, verifying them quickly with browser tools and ZAP, and keeping security in mind across different layers of the app was very helpful in this case. Future improvements could include making the CSP even more precise, running security scans more regularly, and planning security considerations earlier in the design and development process.