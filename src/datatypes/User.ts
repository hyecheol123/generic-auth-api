/**
 * Define type for each user entry
 * Validator also implemented
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import * as ajv from 'ajv';
import {LoginCredentials} from './LoginCredentials';

/**
 * Interface for NewUser
 */
export interface User extends LoginCredentials {
  membersince: string; // in ISO Date format
  admin?: boolean;
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
