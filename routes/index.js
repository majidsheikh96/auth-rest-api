import express from 'express';
const router = express.Router();
import { userController, refreshController, authController } from '../controllers';
import { auth } from '../middlewares';

router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/me', auth, userController.me);
router.post('/refresh', refreshController.refresh);
router.post('/logout', authController.logout);
router.post('/reset-password', authController.reset);
router.post('/update-password', authController.update);


export default router;