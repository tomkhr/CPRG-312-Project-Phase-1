#       Setup instruction

        1.  Make sure MongoDB is running on your machine and is connected to localhost:27017.

        2.  clone this project folder (portfolio-showcase-proj) to your computer.

        3.  Open the folder in VS Code and install dependencies by running this command in the terminal:
                npm install

        4.  a.  Create an .env file in the root folder:
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

            b.      Update the Google IDs with the ones from your Client.

        5.  Start the server by running this command (make sure you have a "dev" script in your package.json):
                npm run dev

        6.  open your browser and go to:
                https://localhost:3443



##      Authentication Mechanisms

            This project uses local authentication using username and password, and Google login for single sign-on.
            When users log in or sign up, passwords are hashed with Argon2 before being stored in the database.
            After logging in, the server creates JWT accesss and refreshes tokens that are stored in HttpOnly cookies.
            Tokens expire after some time, and the system issues new tokens when users refresh their session.
            CSRF protection is enabled, and rate limiting helps prevent repeated failed login attempts.



###     Role-Based Access Control (RBAC)

            The app includes three user roles:
                *   Guest – can only view public posts.
                *   User – can log in, view their profile, create and edit their own posts, and access basic dashboard features.
                *   Admin – has full access to all routes, including managing users, posts, and advanced dashboard features.
            Routes such as /admin, /profile, and /dashboard are only accessible based on each role.



####    Lessons Learned

            During this phase I learned how to combine security and usability when building authentication systems.
            I faced small issues like cookies not showing in Postman because of HTTPS and security flags, but fixed them by turning off SSL verification
            I learned how to handle session protection using CSRF tokens, rate limiting, and secure cookies.
            Overall I also learned that there are more security measures than I initially thought but am very glad to have been able to implement them successfuly and make another step towards being able to build industry-standard real world web application.