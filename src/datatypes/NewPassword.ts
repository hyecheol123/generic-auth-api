/**
 * Define type for New Password.
 * Validator also implemented
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import * as ajv from 'ajv';

/**
 * Interface for NewPassword
 */
export interface NewPassword {
  newPassword: string;
}

// Validator for JSON object containing information of NewPassword
export const validateNewPassword = new ajv().compile({
  type: 'object',
  properties: {
    newPassword: {type: 'string'},
  },
  required: ['newPassword'],
  additionalProperties: false,
});
