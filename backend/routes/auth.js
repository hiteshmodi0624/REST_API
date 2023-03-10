const express = require('express')

const { body, check } = require("express-validator");
const authController = require('../controllers/auth');
const isAuth = require('../middleware/isAuth');
const User = require('../models/user');

const router= express.Router();

router.put(
    "/signup",
    [
        body("email")
            .isEmail()
            .withMessage("Please enter a valid email!")
            .custom((value, { req }) => {
                return User.findOne({ email: value }).then((userDoc) => {
                    if (userDoc) {
                        return Promise.reject("Email address already exist!");
                    }
                });
            })
            .normalizeEmail(),
        body("name").trim().notEmpty(),
        body("password").trim().isLength({ min: 5 }),
    ],
    authController.signup
);
router.post('/login',authController.login)

router.get('/status', isAuth ,authController.getStatus)
router.put('/status', isAuth ,authController.putStatus)

module.exports=router;