# Generic Auth API

[![Code Style: Google](https://img.shields.io/badge/code%20style-google-blueviolet.svg)](https://github.com/google/gts)

Simple template for Auth API using JWT with Bearer Authentication.
Both access token and refresh token are used.

This project only implements very basic authentication features.
The detailed features are listed below.


## Supported APIs

Supported features(APIs) are listed below.

- **Add Users**  
  
  This API let admin user (or other services) to add other user's login credential to the server.

  Username and password are stored in the database.
  Passwords are secured by cryptographic hash function.
  This let the others except for the user, including server admin, not to look up the password.

- **Login** (with username and password)  

  This API let user to signin and retrieve access/refresh tokens from server.  

  Refresh tokens are stored in the database, while access tokens are not stored.
  On the client side, all tokens are stored as the Cookies.

- **Logout**  

  This API clears the related Cookies that store access/refresh token 
  and invalidate refresh token by remove it from the database.

  Only current session will be signed out; other sessions are still active.

- **Logout from other sessions**

  This API removes refresh tokens that are not associated with the current session from the database.

- **Renew Tokens**
  
  This API creates new access token based on the information of the provided refresh token.
  The new access token will replace the old access token.

  Before generating new access token, the server will check whether the refresh token exists in the database.

## Scripts


## Dependencies/Environment


## Contact