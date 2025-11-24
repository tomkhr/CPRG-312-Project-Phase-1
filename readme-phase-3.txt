    1.  Make sure MongoDB is running on your machine and is connected to localhost:27017.

    2.  Clone the project folder (portfolio-showcase-proj) to your computer.

    3.  Open the folder in VS Code and install dependencies by running:
            npm install

    4.  Create an .env file in the root folder:
                PORT=3443
                NODE_ENV=development
                MONGO_URI=mongodb://localhost:27017/devportfolio
                CORS_ORIGIN=http://localhost:3009
                SESSION_SECRET=your_secret_key
                GOOGLE_CLIENT_ID=yourgoogle_client_id
                GOOGLE_CLIENT_SECRET=your_google_client_secret
                GOOGLE_CALLBACK_URL=https://localhost:3443/auth/google/callback
                JWT_SECRET=your_jwt_secret
                JWT_EXPIRES=15m
                REFRESH_SECRET=your_refrehs_secret
                REFRESH_EXPIRES=7d
                RATE_LIMIT_WINDOW_MS=900000
                RATE_LIMIT_MAX=5
                ENC_SECRET=your_enc_secret
                ENC_IV=00000000000000000000000000000000

        Update the Google IDs with the ones from your OAuth Client.

    5.  Start the server by running:
            npm run dev

    6.  Open your browser and go to:
            https://localhost:3443



##      Authentication Mechanisms

                Inputs are cleaned using regular expressions and string trimming. HTML tags are stripped to prevent malicious scripts from being stored in the database. The aplication uses simple validation rules to make sure user inputs are safe and expected.

###     Output Encoding Methods

                The dashboard uses plain text rendering through JavaScript to make sure that any user data shown on the page is treated as text instead of HTML. This prevents XSS attacks because even if someone tries injecting HTML or JavaScript it will never execute in the browser

####    Encryption

                Sensitive fields like email and bio are encrypted using the AES-128-CBC algorithm before they are stored in MongoDB. This makes the values unredable in the DB. When the user loads the dashboard these fields are decrypted on the server and shown in the form in a sanitized format.

#####   Third-Party Library dependency Management

                The project uses standard tools like npm audit and npm outdated to check for vulnerabilities and outdated packages. For automation, a GitHub Actions workflow will run these checks automatically.

######  Lessons Learned

                In this phase I learned how important it is to validate and sanitize user inputs to avoid storing bad data. I also saw how essential output encoding is for stopping XSS attacks. I knew that dependency updates must be done carefully because they can break a working application, but learned that outdated dependencies can be sources of problems and attacks if an attacker decides to exploite some known volnurabilities. Automation can help track issues without making changes automatically.