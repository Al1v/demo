const User = require("../models/user");
const Role = require("../models/role");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const secret = process.env.secret;
const ejs = require('ejs');
const {validationResult} = require('express-validator');
const chalk = require('chalk');



const generateAccessToken = (id, roles) => {
    const payload = {
        id,
        roles
    }
    return jwt.sign(payload, secret, {expiresIn: "3h"} );
} 

class AuthController {
    async postRegister(req, res) {
            console.log(req.body);
            const errors = validationResult(req);
            try{
            let errMsg = "";

            for (let element of errors.errors){
                 errMsg += element.msg + "; ";
            }
             
            if (errMsg){
            
                console.log(errMsg);

                return res.status(400).json(errMsg)
            }
            const {username, password, email} = req.body;
            const candidate = await User.findOne({username});
            if(candidate){
                
                return res.status(400).json("user already exists");
            }
            const hashPassword = bcrypt.hashSync(password, 7);
            const userRole = await Role.findOne({value: "USER"});
            const user = new User({
                username,
                email,
                password: hashPassword, 
                roles: [userRole.value]
            });
            await user.save();
            return res.json( "user has been successfully registered ");
        }catch(err){
   
            console.log(err);

            res.status(400).json("registration error");           
        }
    }
    async postLogin(req, res) {
        try{

            const {email, password} = req.body;
            console.log(email, password);
            const user = await User.findOne({email});
            if (!user){
                return res.status(400).json("User not found");
            }
            const validPassword = bcrypt.compareSync(password, user.password);
            if (!validPassword){
                res.status(400).json('wrong password');
            }
            const accessToken = generateAccessToken(user._id, user.roles); 
            res.cookie("accessToken", accessToken, { maxAge: 10800000, httpOnly: true })
               .redirect('../');

            return 

                

        }catch(err){

            console.log(err);  
            res.status(400).json({message: "login error"});

        }        
    }
    async users(req, res) {
        try{

            const users = await User.find();
            res.render('users', {users: users});

        }catch(err){
            console.log(err); 
             
        }        
    }
    async getLogin(req, res) {

        try{
            let username = "";
            if(req?.user?.username){
                username = req.user.username;
            }
            res.render('auth/login', {username});
        }catch(err){
            console.log(err); 
             
        }        
    }
    async getRegister(req, res) {
        let username = "";
        try{   
            if(req?.user?.username){
                username = req.user.username;
            }
            res.render('auth/register', {username});
        }catch(err){

            console.log(err); 
             
        }    

    }
    async getLogout(req, res) {
        try{

            res.clearCookie('accessToken');
            res.redirect('/auth/login');

        }catch(err){

            console.log(err); 
             
        }        
    }
    async mainPage(req, res) {
        try{
            let username = "";
            if(req?.user?.username){
                username = req.user.username;
            }
            
            res.render('main', {username});
        }catch(err){

            console.log(err); 
             
        }  
    } 
}

module.exports = new AuthController();