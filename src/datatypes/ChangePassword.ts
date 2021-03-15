/**
 * Define type for Chaning Password.
 * Validator also implemented
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import * as ajv from 'ajv';

/**
 * Interface for ChangePassword
 */
export interface ChangePassword {
  currentPassword: string;
  newPassword: string;
}

// Validator for JSON object containing information of ChangePassword
export const validateChangePassword = new ajv().compile({
  type: 'object',
  properties: {
    changePassword: {type: 'string'},
    newPassword: {type: 'string'},
  },
  required: ['changePassword', 'newPassword'],
  additionalProperties: false,
});
