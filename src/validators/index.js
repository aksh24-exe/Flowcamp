import { body } from "express-validator";

const userRegisterValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("Email is required")
      .bail()
      .isEmail()
      .withMessage("Email is invalid"),

    body("username")
      .trim()
      .notEmpty()
      .withMessage("Username is required")
      .bail()
      .isLength({ min: 3 })
      .withMessage("Username must be at least 3 characters long"),

    body("password")
      .trim()
      .notEmpty()
      .withMessage("Password is required")
      .bail()
      .isLength({ min: 8 })
      .withMessage("Password must be at least 8 characters"),

    body("fullName").trim().isEmpty().withMessage("Name is required"),
  ];
};

const userLoginValidator = () => {
  return [
    body("email").optional().isEmail().withMessage("Email is invalid"),
    body("password").notEmpty().withMessage("Password is required"),
  ];
};

const userChangeCurrentPasswordValidator = () => {
  return [
    body("currentPassword")
      .trim()
      .notEmpty()
      .withMessage("Current Password is required"),
    body("newPassword")
      .trim()
      .notEmpty()
      .withMessage("New Password is required")
      .bail()
      .isLength({ min: 8 })
      .withMessage("Password must be at least 8 characters"),
    body("newConfirmPassword")
      .trim()
      .notEmpty()
      .withMessage("Confirm Password is required")
      .bail()
      .isLength({ min: 8 })
      .withMessage("Password must be at least 8 characters"),
  ];
};

const userForgotPasswordValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("Email is required")
      .bail()
      .isEmail()
      .withMessage("Email is invalid"),
  ];
};

const userResetForgotPasswordValidator = () => {
  return [
    body("password")
      .trim()
      .notEmpty()
      .withMessage("Password is required")
      .bail()
      .isLength({ min: 8 })
      .withMessage("Password must be at least 8 characters"),
    body("confirmPassword")
      .trim()
      .notEmpty()
      .withMessage("Confirm Password is required")
      .bail()
      .isLength({ min: 8 })
      .withMessage("Password must be at least 8 characters"),
  ];
};

export {
  userRegisterValidator,
  userLoginValidator,
  userChangeCurrentPasswordValidator,
  userForgotPasswordValidator,
  userResetForgotPasswordValidator,
};
