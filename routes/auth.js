const express = require('express');
const User = require('../models/Users');
const { check, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const auth = require('../middleware/auth');
const jwt = require('jsonwebtoken');
const config = require('config');

const router = express.Router();

//@route       GET api/auth
//@desc        Get logged user
//@access      Private
router.get('/',auth, async (req, res)=> {
    try{
        const user = await User.findById(req.user.id).select('-password');
        console.log(req.user.id);
        res.json(user);
    } catch(err){
        console.log(err.message);
        res.status(500).send('Server Error');
    }
});

//@route       POST api/auth
//@desc        Auth user & get token
//@access      Public
router.post('/', [
  check('email', 'please include a valid email').isEmail(),
  check('password', 'password is required').exists()
],
async (req, res)=> {
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({ errors: errors.array() })
    }

    const {email, password} = req.body;
    try{
        let user= await User.findOne({ email });

        if(!user){
            return res.status(400).json({msg: 'invalid credentials'});
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if(!isMatch){
            return res.status(400).json({msg: 'invalid password'});
        }

        const payload = {
            user: {
                id: user.id
            }
        };
        jwt.sign(payload, config.get('jwtSecret'), {
           expiresIn: 360000
        }, (err, token) => {
            if(err) throw err;
            res.json({ token });
        });

    }catch(err){
        console.log(err.message);
        res.status(500).send('Server error');
    }
});


module.exports = router;