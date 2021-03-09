/**
 * Define type for New User Form, containing login credentials
 * and other informations that needed to create new user properly.
 * Validator also implemented
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import * as ajv from 'ajv';
import {LoginCredentials} from './LoginCredentials';

/**
 * Interface for NewUser
 */
export interface NewUserForm extends LoginCredentials {
  admin?: boolean;
  timestamp: Date; // in JSON Date format
}

// Validator for JSON object containing information of NewUserForm
export const validateNewUserForm = new ajv().compile({
  type: 'object',
  properties: {
    username: {type: 'string'},
    password: {type: 'string'},
    admin: {type: 'boolean'},
    timestamp: {type: 'string', format: 'date-time'},
  },
  required: ['username', 'password', 'timestamp'],
  additionalProperties: false,
});
