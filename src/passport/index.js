import passport from 'passport';
import express from 'express';
import OIDCStrategy from './strategies/AzureActiveDirectory';

export default ({ expressApp = null } = {}) => {
    if (expressApp === null)
        throw new Error('expressApp cannot be null');

    //Initialize Passport
    expressApp.use(passport.initialize());
    expressApp.use(passport.session());

    //Use strategies
    passport.use('AzureActiveDirectory', OIDCStrategy());

    //Serialize User
    passport.serializeUser((user, done) => {
        done(null, JSON.stringify(user));
    });

    //Deserialize User
    passport.deserializeUser((data, done) => {
        try {
            const user = JSON.parse(data);
            done(null, user);
        } catch (err) {
            done(err);
        }
    });

    //Create routes
    const router = express.Router();

    //Login Aad Routes
    router.get('/login', passport.authenticate('azuread-openidconnect'));
    router.get('/auth/openid/return', passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }),
        (req, res) => {
            res.redirect('/');
        }
    );

    return router;
} 