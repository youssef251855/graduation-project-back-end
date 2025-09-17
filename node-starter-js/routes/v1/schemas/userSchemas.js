const Joi = require("joi");
const { JoiObjectId } = require("../../../middlewares/schemaValidator");

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
 *     User:
 *       type: object
 *       properties:
 *         username:
 *           type: string
 *           description: The username
 *         email:
 *           type: string
 *           description: Email address
 *         role:
 *           type: string
 *           description: user role admin or user
 *     UpdateUser:
 *       type: object
 *       properties:
 *         username:
 *           type: string
 *           description: The username
 *         email:
 *           type: string
 *           description: Email address
 *     CreateUser:
 *       type: object
 *       required:
 *         - username
 *         - email
 *         - password
 *         - passwordConfirm
 *       properties:
 *         username:
 *           type: string
 *           description: The username
 *         email:
 *           type: string
 *           description: Email address
 *         password:
 *           type: string
 *           description: Minimum of 8 characters long
 *         passwordConfirm:
 *           type: string
 *           description: Should match with the password
 */


exports.createUser = Joi.object({
    name: Joi.string().trim().min(3).max(30).required(),
    email: Joi.string().min(3).required().email(),
    password: Joi.string().min(8).required().regex(/^[a-zA-Z0-9]{8,30}$/),
    passwordConfirm:Joi.string().min(8).required().valid(Joi.ref('password'))
        .regex(/^[a-zA-Z0-9]{8,30}$/)

});
exports.updateUser = Joi.object({
    username: Joi.string().trim().min(3).max(30).optional(),
    email: Joi.string().min(3).email().optional(),
    password: Joi.string().min(8).regex(/^[a-zA-Z0-9]{8,30}$/).optional(),
    passwordConfirm:Joi.string().min(8).valid(Joi.ref('password'))
        .regex(/^[a-zA-Z0-9]{8,30}$/).optional()

});

exports.getUsers = Joi.object({
    username: Joi.string().trim().min(3).max(30).optional(),
    email: Joi.string().min(3).optional().email(),
    deleted: Joi.boolean().optional(),
    page: Joi.number().optional(),
    perPage: Joi.number().optional(),
    search: Joi.string().optional(),
    sort: Joi.string().optional()

})
exports.checkUserId=Joi.object({
    id:JoiObjectId().required()
})

exports.forgetPassword = Joi.object({
    email:Joi.string().required()
})

exports.resetPasswordToken = Joi.object({
    token:Joi.string().required()
})

exports.resetPassword = Joi.object({
    password: Joi.string().min(8).regex(/^[a-zA-Z0-9]{8,30}$/).required(),
    passwordConfirm:Joi.string().min(8).valid(Joi.ref('password'))
        .regex(/^[a-zA-Z0-9]{8,30}$/).required()
})