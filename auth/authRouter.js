const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const secrets = require('../api/secrets.js');
const Users = require('../users/usersModel.js');

router.post('/register', (req, res) => {
    let user = req.body;

    const rounds = process.env.HASH_ROUNDS || 8;

    const hash = bcrypt.hashSync(user.password, rounds);

    user.password = hash;

    Users.add(user)
    .then(saved => {
        res.status(201).json(saved);
    })
    .catch(error => {
        console.log(error);
        res.status(500).json({
            errorMesage: error.message
        });
    });
});

router.post('/login', (req, res) => {
    let { username, password } = req.body;

    Users.findBy({ username })
    .then(([user]) => {
        if(user && bcrypt.compareSync(password, user.password)) {
            const token = generateToken(user);
            res.status(200).json({
                message: 'Welcome', token
            });
        } else {
            res.status(401).json({
                message: 'You cannot pass'
            });
        };
    })
    .catch(error => {
        console.log(error);
        res.status(500).json({
            errorMessage: error.message
        });
    });
});

router.get('/logout', (req, res) => {
    if (req.session) {
        req.session.destroy(error => {
            if(error) {
                res.status(500).json({
                    errorMessage: 'you can checkout any time you like but you can never leave'
                });
            } else {
                res.status(204).end();
            };
        });
    } else {
        res.status(204).end();
    };
});

function generateToken(user){
    const payload = {
        userId: user.id,
        username: user.username,
        password: user.password
    };
    const secret = secrets.jwtSecret;
    const options = {
        expiresIn: '2d'
    };
    return jwt.sign(payload, secret, options);
}

module.exports = router;