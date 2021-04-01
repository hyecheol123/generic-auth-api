/**
 * Define type for Chaning Password.
 * Validator also implemented
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import * as Ajv from 'ajv';

/**
 * Interface for ChangePassword
 */
export interface ChangePassword {
  currentPassword: string;
  newPassword: string;
}

// Validator for JSON object containing information of ChangePassword
export const validateChangePassword = new Ajv().compile({
  type: 'object',
  properties: {
    currentPassword: {type: 'string'},
    newPassword: {type: 'string'},
  },
  required: ['currentPassword', 'newPassword'],
  additionalProperties: false,
});
