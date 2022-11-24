import Joi from 'joi';
import { User } from '../../models';
import CustomErrorHandler from '../../services/CustomErrorHandler';
import bcrypt from 'bcrypt';
import JwtService from '../../services/JwtService';

const userController = {
    async me(req, res, next) {

        try {
            const user = await User.findOne({ _id: req.user._id }).select(' -password -updatedAt -__v');

            if (!user) {
                return next(CustomErrorHandler.notFound());
            }

            return res.json(user);

        } catch (err) {
            return next(err);
        }
    }
}

export default userController;