const User = require('../models/user');
const Blog = require('../models/blog');
const shortId = require('shortid');
const jwt = require('jsonwebtoken');
const expressJwt = require('express-jwt');
const { errorHandler } = require('../helpers/dbErrorHandler');
const _ = require('lodash');
const { OAuth2Client } = require('google-auth-library');

const sgMail = require('@sendgrid/mail');
const shortid = require('shortid');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

exports.preSignup = (req, res) => {
    const { name, email, password } = req.body;

    User.findOne({ email: email.toLowerCase() }).exec((err, user) => {
        if (user) {
            return res.status(400).json({
                error: 'Email is taken'
            });
        }

        const token = jwt.sign({ name, email, password }, process.env.JWT_ACCOUNT_ACTIVATION, { expiresIn: '10m' });

        const emailData = {
            to: email,
            from: process.env.EMAIL_FROM,
            subject: `Account activation link - ${ process.env.APP_NAME }`,
            html: `
                <h4>Please use the following link to activate your account:</h4>
                <p>${ process.env.CLIENT_URL }/auth/account/activate/${ token }</p>
                <hr/>
                <p>This email may contain sensitive information</p>
                <p>https://seoblog.com</p>`
        };

        sgMail.send(emailData).then(sent => {
            return res.json({
                message: `Email has been sent to ${ email }. Follow the instructions to activate your account.`
            })
        }, err => {
            console.log(err);
        });
    });
};

// exports.signup = (req, res) => {
//     User.findOne({ email: req.body.email }).exec((err, user) => {
//         if (user) {
//             return res.status(400).json({
//                 error: 'Email is taken'
//             })
//         }

//         const { name, email, password } = req.body;
//         let username = shortId.generate();
//         let profile = `${process.env.CLIENT_URL}/profile/${username}`;

//         let newUser = new User({ name, email, password, profile, username });
//         newUser.save((err, success) => {
//             if (err) {
//                 return res.status(400).json({
//                     error: 'Could not save new user'
//                 })
//             }
//             return res.json({
//                 message: 'Sign up success! Please sign in.'
//             })
//         })
//     })
// };

exports.signup = (req, res) => {
    const token = req.body.token;

    if (token) {
        jwt.verify(token, process.env.JWT_ACCOUNT_ACTIVATION, function(err, decoded) {
            if (err) {
                return res.status(401).json({
                    error: 'Expired link. Please sign up again.'
                });
            }

            const { name, email, password } = jwt.decode(token);

            let username = shortId.generate();
            let profile = `${process.env.CLIENT_URL}/profile/${username}`;

            const user = new User({ name, email, password, profile, username });
            user.save((err, user) => {
                if (err) {
                    return res.status(401).json({
                        error: errorHandler(err)
                    });
                }

                return res.json({
                    message: 'Sign up successful! Please sign in.'
                });
            });
        });
    } else {
        return res.json({
            message: 'Something went wrong. Please try again.'
        });
    }
};

exports.signin = (req, res) => {
    const { email, password } = req.body;
    // check if user exists
    User.findOne({ email: email }).exec((err, user) => {
        if (err || !user) {
            return res.status(400).json({
                error: "User with that email does not exist. Please sign up."
            });
        }

        // authenticate
        if (!user.authenticate(password)) {
            return res.status(400).json({
                error: "Email and password do not match."
            });
        }

        // generate a token and send to client
        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

        res.cookie('token', token, { expiresIn: '1d' });
        const { _id, username, name, role } = user;
        return res.json({
            token: token,
            user: { _id, username, name, email, role }
        });
    })
};

exports.signout = (req, res) => {
    res.clearCookie('token');
    res.json({
        message: 'Signout success'
    });
};

exports.requireSignin = expressJwt({
    secret: process.env.JWT_SECRET,
    algorithms: ["HS256"],
    userProperty: "auth",
});

exports.authMiddleware = (req, res, next) => {
    const authUserId = req.auth._id;

    User.findById({ _id: authUserId }).exec((err, user) => {
        if (err || !user) {
            return res.status(400).json({
                error: 'User not found'
            });
        }

        req.profile = user;
        next();
    });
};

exports.adminMiddleware = (req, res, next) => {
    const adminUserId = req.auth._id;

    User.findById({ _id: adminUserId }).exec((err, user) => {
        if (err || !user) {
            return res.status(400).json({
                error: 'User not found'
            });
        }

        if (user.role !== 1) {
            return res.status(400).json({
                error: 'Admin resource. Access denied'
            });
        }

        req.profile = user;
        next();
    });
};

exports.canUpdateDeleteBlog = (req, res, next) => {
    const slug = req.params.slug.toLowerCase();

    Blog.findOne({ slug: slug }).exec((err, data) => {
        if (err) {
            return res.status(400).json({
                error: errorHandler(err)
            })
        }

        let authorizedUser = data.postedBy._id.toString() === req.profile._id.toString();
        if (!authorizedUser) {
            return res.status(400).json({
                error: 'You are not authorized'
            })
        }
        next();
    });
};

exports.forgotPassword = (req, res) => {
    const { email } = req.body;

    User.findOne({ email: email }).exec((err, user) => {
        if (err || !user) {
            return res.status(401).json({
                error: 'User with that email does not exist'
            });
        }

        const token = jwt.sign({ _id: user._id }, process.env.JWT_RESET_PASSWORD, { expiresIn: '10m' });

        const emailData = {
            to: email,
            from: process.env.EMAIL_FROM,
            subject: `Password reset link - ${ process.env.APP_NAME }`,
            html: `
                <h4>Please use the following link to reset your password:</h4>
                <p>${ process.env.CLIENT_URL }/auth/password/reset/${ token }</p>
                <hr/>
                <p>This email may contain sensitive information</p>
                <p>https://seoblog.com</p>`
        };

        return user.updateOne({ resetPasswordLink: token }).exec((err, success) => {
            if (err) {
                return res.json({ error: errorHandler(err) });
            } else {
                sgMail.send(emailData).then(sent => {
                    return res.json({
                        message: `Email has been sent to ${ email }. Follow the instructions to reset your password. Link expires in 10 minutes.`
                    });
                }, err => {
                    console.log(err);
                });
            }
        });
    });
};

exports.resetPassword = (req, res) => {
    const { resetPasswordLink, newPassword } = req.body;

    if (resetPasswordLink) {
        jwt.verify(resetPasswordLink, process.env.JWT_RESET_PASSWORD, function(err, decoded) {
            if (err) {
                return res.status(401).json({
                    error: 'Expired link. Try again'
                });
            }

            User.findOne({ resetPasswordLink: resetPasswordLink }).exec((err, user) => {
                if (err || !user) {
                    return res.status(401).json({
                        error: 'Something went wrong. Try later'
                    });
                }

                const updatedFields = {
                    password: newPassword,
                    resetPasswordLink: ''
                }

                user = _.extend(user, updatedFields);

                user.save((err, result) => {
                    if (err) {
                        return res.status(400).json({
                            error: errorHandler(err)
                        });
                    }

                    return res.json({
                        message: `Great! Now you can log in with your new password.`
                    });
                });
            });
        });
    }
};

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

exports.googleLogin = (req, res) => {
    const idToken = req.body.tokenId;

    client.verifyIdToken({ idToken, audience: process.env.GOOGLE_CLIENT_ID }).then(response => {
        const { email_verified, name, email, jti } = response.payload;

        if (email_verified) {
            User.findOne({ email: email }).exec((err, user) => {
                if (user) {
                    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

                    res.cookie('token', token, { expiresIn: '1d' });
                    const { _id, username, name, email, role } = user;
                    return res.json({
                        token: token,
                        user: { _id, username, name, email, role }
                    });
                } else {
                    let username = shortId.generate();
                    let profile = `${ process.env.CLIENT_URL }/profile/${ username }`;
                    let password = jti + process.env.JWT_SECRET;

                    user = new User({ name, email, profile, username, password });
                    user.save((err, data) => {
                        if (err) {
                            return res.status(400).json({
                                error: errorHandler(err)
                            });
                        }

                        const token = jwt.sign({ _id: data._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

                        res.cookie('token', token, { expiresIn: '1d' });
                        const { _id, username, name, email, role } = data;
                        return res.json({
                            token: token,
                            user: { _id, username, name, email, role }
                        });
                    });

                }
            });
        } else {
            return res.status(400).json({
                error: 'Google login failed. Please try again.'
            });
        }
    });
};