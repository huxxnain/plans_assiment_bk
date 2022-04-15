const express = require('express');
const userController = require('../controllers/userController');
const authController = require('../controllers/authController');



const router = express.Router();

router.post('/signup',authController.signup)
router.post('/login',authController.login)
router.post('/forgotPassword',authController.forgotPassword)
router.post('/sign-in/google',authController.googleSignIn);
router.patch('/resetPassword/:token', authController.resetPassword);
router.patch('/updateMyPassword',authController.protect, authController.updatePassword);
router.patch('/updateGooglePassword',authController.protect, authController.updateGooglePassword);
router.patch('/updateMe',authController.protect,userController.uploadUserPhoto,userController.resizeUserPhoto, userController.updateMe);
router.patch('/verify',authController.protect, userController.updateStatus);
router.patch('/:id/updatePlan/:plan_id',authController.protect, authController.updateUserPlan);
router.get('/user/:id/stats',authController.protect, userController.getStats);

router
  .route('/')
  .get(userController.getAllUsers)
  .post(userController.createUser);

router
  .route('/:id')
  .get(userController.getUser)
  .patch(userController.updateUser)
  .delete(userController.deleteUser);

module.exports = router;
