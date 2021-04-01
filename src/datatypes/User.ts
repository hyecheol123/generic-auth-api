/**
 * Define type for each user entry
 * Validator also implemented
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import * as Ajv from 'ajv';
import {LoginCredentials} from './LoginCredentials';

/**
 * Interface for NewUser
 */
export interface User extends LoginCredentials {
  membersince: string | Date; // in ISO Date format
  admin?: boolean;
}

// Validator for JSON object containing information of NewUserForm
export const validateNewUserForm = new Ajv().compile({
  type: 'object',
  properties: {
    username: {type: 'string'},
    password: {type: 'string'},
    admin: {type: 'boolean'},
    membersince: {type: 'string', format: 'date-time'},
  },
  required: ['username', 'password', 'membersince'],
  additionalProperties: false,
});
