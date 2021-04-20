const router = require('express').Router();
const bcrypt = require('bcryptjs');
const app = require('../app');
const UserModel = require('../models/User.model')
let isLoggedIn = false;

//signup routes
router.get('/signup', (req, res)=>{
    res.render('signup.hbs')
})

router.post('/signup', (req, res, next)=>{
    const {username, password} = req.body

    const salt = bcrypt.genSaltSync(12);
    const hash = bcrypt.hashSync(password, salt);

    UserModel.create({username, password: hash})
    .then(()=>{
        res.redirect('/')
    })
    .catch(()=>{
        next('Sign up impossible')
    })
})

//signin routes
router.get('/signin', (req, res)=>{
    res.render('signin.hbs')
})

router.post('/signin', (req, res, next)=>{
    const {username, password} = req.body

    UserModel.findOne({username})
    .then((response)=>{
        if(!response) {
            res.render('signin.hbs', {msg: 'Please check your username and password'})
        } else {
            bcrypt.compare(password, response.password)
            .then((isMatching)=>{
                if(isMatching){
                    req.session.userInfo = response
                    isLoggedIn = true
                    res.redirect('/main')
                    
                } else {
                    res.redirect('/signin', {msg:'Username or password seems incorrect'})
                }
            })
        }
    })
    .catch((err)=>{
        next(err)
    })
})

//midlleware
const authorize = (req, res, next)=>{
    if(req.session.userInfo){
        next()
    } else {
        res.redirect('/signin')
    }
}


router.get('/main', authorize, (req, res, next)=>{
        res.render('main.hbs')
})

router.get('/private', authorize, (req, res, next)=>{
     res.render('private.hbs')
})

module.exports = router