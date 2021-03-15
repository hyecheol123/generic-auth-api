# Generic Auth API

[![Code Style: Google](https://img.shields.io/badge/code%20style-google-blueviolet.svg)](https://github.com/google/gts)

Simple template for Auth API using JWT with Bearer Authentication.
Both access token and refresh token are used.

This project only implements very basic authentication features.
The detailed features are listed below.


## Supported APIs

- **Login** `POST /login` (with username and password)  

  This API let user to signin and retrieve access/refresh tokens from server.  

  Refresh tokens are stored in the database, while access tokens are not stored.
  On the client side, all tokens are stored as the Cookies.

  Cookie parameter name for access token is `X-ACCESS-TOKEN`, 
  and refresh token is `X-REFRESH-TOKEN`.

  **NOTE THAT COOKIE SECURITY OPTIONS ARE NOT SET**  
  - Need to set token and cookie's path, domain, and secured option.  

  **NOTE THAT ONLY ONE SUCCESS LOGIN PER SECOND**

- **Logout** `DELETE /logout`  

  This API clears the related Cookies that store access/refresh token 
  and invalidate refresh token by remove it from the database.

  Only current session will be signed out; other sessions are still active.

- **Logout from other sessions** `DELETE /logout/other-sessions`

  This API removes refresh tokens that are not associated with the current session from the database.

- **Change Password**
  
  This API let users to change their password.
  It requires user's current password.

- **Renew Tokens** `GET /renew`
  
  This API creates new access token based on the information of the provided refresh token.
  The new access token will replace the old access token.

  Before generating new access token, the server will check whether the refresh token exists in the database.


## Supported Admin APIs

Supported features(APIs) are listed below.

- **Add Users** `POST /admin/user`  
  
  This API let admin user (or other services) to add other user's login credential to the server.

  Username and password are stored in the database.
  Passwords are secured by cryptographic hash function.
  This let the others except for the user, including server admin, not to look up the password.

- **Remove Users** `DELETE /admin/user/{username}`  

  This API let admin user (or other services) to remove existing user's login credential from the server.  

  Cannot delete admin account that currently running this API.
  Will also logout from all sessions associated with the account.

- **Reset Password** `PUT /admin/user/{username}/password`
  
  This API let admin to reset user's password without user's current password.

  This can be used to send user a temporal password.


## Scripts

Here is the list for supported npm/yarn scripts.
These are used to lint, test, build, and run the code.

1. `lint`: lint the code
2. `lint:fix`: lint the code and try auto-fix
3. `compile`: compile typescript codes (destination: `dist` directory)
4. `clean`: remove the compiled code
5. `start`: run the codes
6. `test`: run the test codes


## Dependencies/Environment

Developed and tested with `Ubuntu 20.04.2 LTS`, with `Node v14.16.0`.

To configure the typescript development environment easily, [gts](https://github.com/google/gts) has been used.
Based on the `gts` style rules, I modified some to enforce rules more strictly.
To see the modification, please check [`.eslintrc.json` file](https://github.com/hyecheol123/generic-auth-api/blob/main/.eslintrc.json).

For the database, this project is relying on [MariaDB](https://mariadb.org/), which almost identical with the MySQL.
In this project, all informations are stored in `auth_api` database.  

SQL Query to create `user` table is 
``` SQL
CREATE TABLE user (
  username VARCHAR(12) NOT NULL PRIMARY KEY,
  password CHAR(88) NOT NULL,
  membersince TIMESTAMP NULL DEFAULT NULL,
  admin BOOLEAN NOT NULL);
```

SQL Query to create `session` table is
``` SQL
CREATE TABLE session (
  token VARCHAR(400) NOT NULL PRIMARY KEY,
  expiresAt TIMESTAMP NULL DEFAULT NULL,
  username VARCHAR(12) NOT NULL,
  INDEX usernameIdx(username));
```

[Express](https://expressjs.com/) is a web framework for node.js.
This project used it to develop and maintain APIs more conveniently.

[ajv](https://ajv.js.org/) is used for runtime type checks.