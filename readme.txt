# Setup instruction

    1.   Make sure MongoDB is running on your machine and is connected to localhost:27017

    2.   Clone the project folder of this project to your machine.

    3.   Install dependencies by running the following command in terminal:
            npm Install

    4.   Create an ".env" file in the root folder and paste the follwing code in it: 
            PORT=3443
            NODE_ENV=development
            MONGO_URI=mongodb://localhost:27017/devportfolio
            CORS_ORIGIN=http://localhost:3000

    5.   Start the server by running the following command (ensure dev script is included in package.json):
            npm run dev

    6.   Open your browser at "https://localhost:3443" to check if server is running. Your should see a message that confirms your HTTPS server with Helmet is running securely.

-------------------

# SSL Configuration:
    - Used self-signed SSL certs (key.pem and cert.pem) in the /certs folder.  
    - Integrated SSL into the HTTPS server.  
    - Added Helmet middleware for security headers like Content Security Policy and X-Frame-options as well as all the other built in headers.

-------------------

# Caching Strategies:
    - GET to psots cached for 5 minutes with stale-while-revalidate.
    - GET requests for posts with specific id are cached individually for 5 minutes with private posts only visible to admin and dev users.  
    - POST, PUT, DELETE routes are not cached.

-------------------

# Lessons Learned:
    - Learned how to set up HTTPS with self-signed certificates.  
    - Learned how to use role-based access to protect private posts and was able to wrap my head around how it's all structured which was difficult before.  
    - Figured out that using inspect panel in browser will not allow to view private posts and practiced using Postman and setting up headers to imitate roles in routes.