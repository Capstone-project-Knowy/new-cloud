# Knowy App Backend
Welcome to the place where the backend of this application's hard work pays off! 
## Programming Language
So basicly, we're using two API's for the Backend and inevitably we have to use 2 different languages:
1. Javascript
2. Python
## Framework
The framework used in this project is Express.js, a minimal and flexible Node.js web application framework. Express.js provides a robust set of features for building single and multi-page, as well as hybrid web applications. It facilitates the development of APIs by providing a thin layer of fundamental web application features without obscuring Node.js features that developers know and love. Express.js is used in conjunction with other technologies like JSON Web Tokens (JWT) for authorization and Firestore for the database, creating a cohesive and efficient backend system.
## Authentication & Authorization
The authorization and token system implemented in this project is crucial for ensuring that only authorized users can access and modify data within the application. When a user logs into the system, they receive a token generated using JSON Web Token (JWT). This token contains encrypted information such as the user's email and user ID, which is necessary for verifying their identity with each request made to the server.
## Database
The database used in this project is Google Firestore, a flexible, scalable and real-time NoSQL database. Firestore enables efficient data storage and retrieval, thus allowing applications to handle dynamic and complex queries. Firestore supports real-time updates, which ensures that any changes to the data are immediately reflected across all clients.
