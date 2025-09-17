const Joi = require("joi");

/**
 * @swagger
 * components:
 *   securitySchemes:
 *      bearerAuth:
 *          type: http
 *          scheme: bearer
 *          bearerFormat: JWT
 */
/**
 * @swagger
 * components:
 *   schemas:
 *     Password:
 *       type: object
 *       properties:
 *         currentPassword:
 *          type: string
 *          description: user's current password
 *         newPassword:
 *          type: string
 *          description: user's new password
 *         newPasswordConfirm:
 *          type: string
 *          description: user's new password confirmation
 *     LoginSchema:
 *       type: object
 *       required:
 *         - email
 *         - password
 *       properties:
 *         email:
 *           type: string
 *           description: Email address
 *         password:
 *           type: string
 *           description: Minimum of 8 characters long
 *     UpdatePassword:
 *       type: object
 *       properties:
 *         currentPassword:
 *          type: string
 *          description: user's current password
 *         newPassword:
 *          type: string
 *          description: user's new password
 *         newPasswordConfirm:
 *          type: string
 *          description: user's new password confirmation
 *     ForgetPassword:
 *       type: object
 *       properties:
 *         email:
 *          type: string
 *          description: user's email
 *     ResetPassword:
 *       type: object
 *       properties:
 *         password:
 *          type: string
 *          description: user's new password
 *         passwordConfirm:
 *          type: string
 *          description: user's new password
 *     VerifyEmail:
 *       type: object
 *       properties:
 *         email:
 *          type: string
 *          description: user's email
 *
 */

exports.signup = Joi.object().keys({
    username: Joi.string().min(3).max(30).required(),
    email: Joi.string().min(3).required().email(),
    password: Joi.string().min(8).required().regex(/^[a-zA-Z0-9]{8,30}$/),
    passwordConfirm:Joi.string().min(8).required().valid(Joi.ref('password'))
        .regex(/^[a-zA-Z0-9]{8,30}$/)
});

exports.login=Joi.object({
    email: Joi.string().min(3).required().email(),
    password: Joi.string().min(8).required().regex(/^[a-zA-Z0-9]{8,30}$/)
})

exports.updatePassword=Joi.object().keys({
    currentPassword:Joi.string().required().regex(/^[a-zA-Z0-9]{8,30}$/),
    newPassword: Joi.string().min(8).required().regex(/^[a-zA-Z0-9]{8,30}$/),
    newPasswordConfirm:Joi.string().min(8).required().valid(Joi.ref('newPassword'))
        .regex(/^[a-zA-Z0-9]{8,30}$/)
})

exports.updateMe=Joi.object().keys({
    username: Joi.string().trim().min(3).max(30).optional(),
    email:Joi.string().email().optional()
})
exports.verifyEmail = Joi.object({
    email:Joi.string().required()
})