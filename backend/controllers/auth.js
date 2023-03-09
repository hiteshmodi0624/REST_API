const User = require("../models/user");
const bcrypt=require('bcrypt')
const jwt=require('jsonwebtoken')

const { validationResult } = require("express-validator");

const Error500=(err,next) => {
    if (!err.statusCode) {
        err.statusCode = 500;
    }
    next(err);
}

exports.signup = async(req,res,next)=>{
    const email=req.body.email
    const name=req.body.name
    const password=req.body.password
    try {
        const errors= validationResult(req);
        if(!errors.isEmpty()){
            const error=new Error("Validation Failed, entered data is incorrect")
            error.statusCode=422;
            error.data=errors.array()
            throw error;
        }
        const hashedPassword=await bcrypt.hash(password,12);
        const user=new User({
            email,
            name,
            password:hashedPassword,
        })
        const result=await user.save()
        res.status(201).json({ message: "User Created", userId: result._id });
    } catch (error) {
        Error500(error,next)
    }
    
}
exports.login = async(req,res,next)=>{
    const email=req.body.email
    const password=req.body.password
    try {
        const user=await User.findOne({email})
        if(!user){
            const error=new Error("A user with this email could not be found.")
            error.statusCode=401;
            throw error;
        }
        const isEqual=await bcrypt.compare(password,user.password)
        if(!isEqual){
            const error=new Error("Incorrect Password.")
            error.statusCode=401;
            throw error;
        }
        const token = jwt.sign(
            { email: user.email, userId: user._id.toString() },
            "superrrrrsecret",
            { expiresIn: "1h" }
        );
        res.status(200).json({token,userId:user._id.toString()});
    } catch (error) {
        Error500(error,next)
    }
}

exports.getStatus=async(req,res,next)=>{
    try {
        const user=await User.findById(req.userId);
        if(!user){
            throw new Error('User not authenticated').statusCode=201
        }
        else{
            res.status(200).json({status:user.status})
        }
    } catch (error) {
        Error500(error,next)
    }
}

exports.putStatus=async(req,res,next)=>{
    const status=req.body.status;
    try {
        const user=await User.findById(req.userId);
        if(!user){
            throw new Error('User not authenticated').statusCode=201
        }
        user.status=status;
        res.status(200).json({ result });
    } catch (error) {
        Error500(error,next)
    }
}