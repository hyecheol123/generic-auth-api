/**
 * Define type for login credentials: username and password.
 * Validator also implemented
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import Ajv from 'ajv';

/**
 * Interface for LoginCredentials
 */
export interface LoginCredentials {
  username: string;
  password: string;
}

// Validator for JSON object containing information of LoginCredentials
export const validateLoginCredentials = new Ajv().compile({
  type: 'object',
  properties: {
    username: {type: 'string'},
    password: {type: 'string'},
  },
  required: ['username', 'password'],
  additionalProperties: false,
});
