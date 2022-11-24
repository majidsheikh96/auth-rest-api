import Joi from 'joi';
import { RefreshToken, User } from '../models';
import CustomErrorHandler from '../services/CustomErrorHandler';
import bcrypt from 'bcrypt';
import { JwtService, EmailService, EmailTemplate } from '../services';
import { APP_NAME, RESET_SECRET, REFRESH_SECRET, CLIENT_APP_URL, MAIL_USER } from '../config';

const authController = {

    async register(req, res, next) {

        // Validation
        const registerSchema = Joi.object({
            username: Joi.string().min(3).max(30).required(),
            email: Joi.string().email().required(),
            password: Joi.string().pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')).required(),
            confirm_password: Joi.ref('password')
        });

        const { error } = registerSchema.validate(req.body);

        if (error) {
            return next(error);
        }

        try {
            const exist = await User.exists({ $or: [ {email: req.body.email}, {username: req.body.username}  ]});
            if (exist) {
                return next(CustomErrorHandler.alreadyExist('This username or email is already taken'));
            }
        } catch (err) {
            return next(err);
        }

        const { username, email, password } = req.body;

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        //  prepare the model
        const user = new User({ username, email, password: hashedPassword });
        let access_token;
        let refresh_token;
        try {
            const result = await user.save();
            access_token = JwtService.sign({ _id: result._id, role: result.role });
            refresh_token = JwtService.sign({ _id: result._id, role: result.role }, '1y', REFRESH_SECRET);

            // database whitelist
            await RefreshToken.create({ token: refresh_token});
        } catch (err) {
            return next(err);
        }

        res.json({access_token, refresh_token});
    },

    async login(req, res, next) {

        // Validation
        const loginSchema = Joi.object({
            email: Joi.string().email().required(),
            password: Joi.string().pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')).required(),
        });

        const { error } = loginSchema.validate(req.body);

        if (error) {
            return next(error);
        }

        try {
            const user = await User.findOne({ email: req.body.email });

            if (!user) {
                return next(CustomErrorHandler.wrongCredentials());
            }

            // compare the password
            const match = await bcrypt.compare(req.body.password, user.password);
            if (!match) {
                return next(CustomErrorHandler.wrongCredentials());
            }

            // Token
            const access_token = JwtService.sign({ _id: user._id, role: user.role });
            const refresh_token = JwtService.sign({ _id: user._id, role: user.role }, '1y', REFRESH_SECRET);

            await RefreshToken.create({ token: refresh_token});

            return res.json({ access_token, refresh_token });
            
        } catch (err) {
            return next(err);
        }
    },
    
    async logout(req, res, next) {
        // validation
        const refreshSchema = Joi.object({
            refresh_token: Joi.string().required(),
        });
        const { error } = refreshSchema.validate(req.body);

        if (error) {
            return next(error);
        }

        try {
            await RefreshToken.deleteOne({ token: req.body.refresh_token });
        } catch(err) {
            return next(new Error('Something went wrong in the database'));
        }
        res.json({ status: 1 });
    },

    async reset(req, res, next) {

        const resetSchema = Joi.object({
            email: Joi.string().email().required()
        });

        const { error } = resetSchema.validate(req.body);

        if (error) {
            return next(error);
        }

        let user;

        try {
            user = await User.findOne({ email: req.body.email }).select(' -__v -role -createdAt -updatedAt');

            if (!user) {
                return next(CustomErrorHandler.alreadyExist('User not registered'));
            }
        } catch (err) {
            return next(err);
        }

        const secrect = RESET_SECRET + user.password;
        const payload = {
            id: user._id
        }
        const token = JwtService.sign(payload, '15m', secrect);
        const resetLink = `${CLIENT_APP_URL}/reset-password/${user._id}/${token}`;

        try {
            await EmailService.sendMail({
                from: `${APP_NAME} <${MAIL_USER}>`,
                to: user.email,
                subject: `${APP_NAME} sent you password reset link`,
                text: '',
                html: EmailTemplate.passwordReset(user.username, resetLink, '15 mins')
            })

            return res.json({success: true});
        } catch (err) {
            return next(err)
        }
    },

    async update(req, res, next) {

        const { id, token, password } = req.body;

        const passwordSchema = Joi.object({
            id: Joi.string().required(),
            token: Joi.string().required(),
            password: Joi.string().pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')).required(),
            confirm_password: Joi.ref('password')
        });

        const { error } = passwordSchema.validate(req.body);

        if (error) {
            return next(error);
        }

        let user;
        try {
            user = await User.findOne({ _id: id });
            if (!user) {
                return next(CustomErrorHandler.unAuthorized());
            }
        } catch (err) {
            return next(err);
        }

        const secrect = RESET_SECRET + user.password;

        let payload;
        try {
            payload = await JwtService.verify(token, secrect);
            if (!payload) {
                return next(CustomErrorHandler.unAuthorized('Invalid token'));
            }
        } catch (err) {
            return next(CustomErrorHandler.unAuthorized('Invalid token'));
        }

        let access_token;
        let refresh_token;

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        try {
            const user = await User.findOneAndUpdate({ _id: payload.id }, { password: hashedPassword })
            access_token = JwtService.sign({ _id: user._id, role: user.role });
            refresh_token = JwtService.sign({ _id: user._id, role: user.role }, '1y', REFRESH_SECRET);

            // database whitelist
            await RefreshToken.create({ token: refresh_token });

        } catch (err) {
            return next(err);
        }

        res.json({ access_token, refresh_token });
    }
}

export default authController;