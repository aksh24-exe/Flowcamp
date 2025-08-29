import { Router } from "express";
import {
  registerUser,
  login,
  logoutUser,
  getCurrentUser,
  verifyEmail,
  resendEmailVerification,
  refreshAccessToken,
  forgetPasswordRequest,
  resetForgetPassword,
  changedCurrentPassword,
} from "../controllers/auth.controllers.js";
import { validate } from "../middlewares/validator.middleware.js";
import {
  userRegisterValidator,
  userLoginValidator,
  userChangeCurrentPasswordValidator,
  userForgotPasswordValidator,
  userResetForgotPasswordValidator,
} from "../validators/index.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();

// unsecured route
router.route("/register").post(userRegisterValidator(), validate, registerUser);
router.route("/login").post(userLoginValidator(), validate, login);
router.route("/verify-email/:verificationToken").get(verifyEmail);
router.route("/refresh-token").post(refreshAccessToken);
router
  .route("/forgot-password")
  .post(userForgotPasswordValidator(), forgetPasswordRequest);
router
  .route("reset-password/:resetToken")
  .post(userResetForgotPasswordValidator(), resetForgetPassword);

// secured route
router.route("/logout").post(verifyJWT, logoutUser);
router
  .route("resend-email-verification")
  .post(verifyEmail, resendEmailVerification);
router
  .route("change-password")
  .post(userChangeCurrentPasswordValidator(), validate, changedCurrentPassword);
router.route("current-user").get(verifyJWT, getCurrentUser);

export default router;
