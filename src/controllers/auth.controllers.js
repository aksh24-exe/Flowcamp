import { User } from "../models/user.models.js";
import { ApiResponse } from "../utils/api-responses.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";
import { emailVerificationMailgenContent, sendEmail } from "../utils/mail.js";
import jwt from "jsonwebtoken";

const generateAccessandRefreshToken = async (userId) => {
  try {
    const user = await User.findById(userId);

    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;

    console.log(user.refreshToken);

    await user.save({ validateBeforeSave: false });
    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(500, "Something went wrong while generate access token");
  }
};

const registerUser = asyncHandler(async (req, res) => {
  const { email, username, password, role } = req.body;

  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existedUser) {
    throw new ApiError(409, "User with email or username already exists", []);
  }

  const user = await User.create({
    email,
    password,
    username,
    isEmailVerified: false,
  });

  const { unHashedToken, hashToken, tokenExpiry } =
    user.generateTemporaryToken();

  (await user).emailVerificationToken = hashToken;
  (await user).emailVerificationExpiry = tokenExpiry;

  (await user).save({ validateBeforeSave: false });

  await sendEmail({
    email: (await user)?.email,
    subject: "Please Verified the email",
    mailgenContent: emailVerificationMailgenContent(
      (await user).username,
      `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`,
    ),
  });

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken -emailVerificationToken -emailVerificationExpiry",
  );

  if (!createdUser) {
    throw new ApiError(500, "Something Went Wrong while registerd a user");
  }

  return res
    .status(201)
    .json(
      new ApiResponse(
        200,
        { user: createdUser },
        "User register successfully and verification email has been send on your email",
      ),
    );
});

const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  // console.log("1");

  if (!email || !password) {
    throw new ApiError(400, "email or password is required");
  }
  // console.log("2");
  const user = await User.findOne({ email });
  // console.log("3");
  if (!user) {
    throw new ApiError(400, "User does not exists");
  }
  // console.log("4");
  const isPasswordValid = await user.isPasswordCorrect(password);
  console.log("5");
  if (!isPasswordValid) {
    throw new ApiError(400, "Invalid credentials");
  }
  // console.log("6");
  console.log(user._id);

  const { accessToken, refreshToken } = await generateAccessandRefreshToken(
    user._id,
  );
  // console.log("7");
  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken -emailVerificationToken -emailVerificationExpiry",
  );
  // console.log("8");
  const option = {
    httpOnly: true,
    secure: true,
  };
  // console.log("9");
  return res
    .status(200)
    .cookie("accessToken", accessToken, option)
    .cookie("refreshToken", refreshToken, option)
    .json(
      new ApiResponse(200, {
        user: loggedInUser,
        accessToken,
        refreshToken,
      }),
      "User logged in successfully",
    );
});

const logoutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: "",
      },
    },
    {
      new: true,
    },
  );
  const option = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .clearCookie("accessToken", option)
    .clearCookie("refreshToken", option)
    .json(new ApiResponse(200, {}, "User logged out"));
});

const getCurrentUser = asyncHandler(async (req, res) => {
  return res
    .status(200)
    .json(new ApiResponse(200, req.user, "Current User fetched successfully"));
});

const verifyEmail = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params;

  if (!verificationToken) {
    throw new ApiError(400, "Email verification token is missing");
  }

  let hashToken = crypto
    .createdUser("sha256")
    .update(verificationToken)
    .digest("hex");

  const user = await User.findOne({
    emailVerificationToken: hashToken,
    emailVerificationExpiry: { $gt: Date.now() },
  });

  if (!user) {
    throw new ApiError(400, "Token is Expired");
  }

  user.emailVerificationExpiry = undefined;
  user.emailVerificationToken = undefined;

  user.isEmailVerified = true;
  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, { isEmailVerified: true }, "Email is verified"));
});

const resendEmailVerification = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user?._id);

  if (!user) {
    throw new ApiError(404, "User does not exist");
  }

  if (!user.isEmailVerified) {
    throw new ApiError(409, "Email is already Verified");
  }

  const { unHashedToken, hashToken, tokenExpiry } =
    user.generateTemporaryToken();

  (await user).emailVerificationToken = hashToken;
  (await user).emailVerificationExpiry = tokenExpiry;

  (await user).save({ validateBeforeSave: false });

  await sendEmail({
    email: (await user)?.email,
    subject: "Please Verified the email",
    mailgenContent: emailVerificationMailgenContent(
      (await user).username,
      `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`,
    ),
  });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Mail has been send to the EmailId"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;

  if (!incomingRefreshToken) {
    throw new ApiError(401, "Unauthorized Token");
  }

  try {
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET,
    );

    const user = await User.findById(decodedToken?._id);
    if (!use) {
      throw new ApiError(401, "Invalid refresh token");
    }

    if (incomingRefreshToken !== use?.refreshToken) {
      throw new ApiError(401, "Refresh token is expired");
    }

    const option = {
      httpOnly: true,
      secure: true,
    };

    const { accessToken, refreshToken: newrefreshToken } =
      await generateAccessandRefreshToken(user._id);

    user.refreshToken = newrefreshToken;
    await user.save({ validateBeforeSave: false });

    return res
      .status(200)
      .cookies("accessToken", accessToken, option)
      .cookies("refreshToken", newrefreshToken, option)
      .json(
        new ApiResponse(
          200,
          { accessToken, newrefreshToken },
          "AccessToken and RefreshToken",
        ),
      );
  } catch (error) {
    throw new ApiError(401, "Invalid refreshToken");
  }
});

const forgetPasswordRequest = asyncHandler(async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    throw new ApiError(404, "User does not exist");
  }

  const { unHashedToken, hashToken, tokenExpiry } =
    user.generateTemporaryToken();

  user.forgotPasswordToken = unHashedToken;
  user.forgotPasswordExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  await sendEmail({
    email: (await user)?.email,
    subject: "Password Reset Email",
    mailgenContent: forgetPasswordMailgenContent(
      (await user).username,
      `${process.env.FORGOT_PASSWORD_REDIRECT_URL}/${unHashedToken}`,
    ),
  });

  return res.status(200).json(new ApiResponse(200, {}, "Mail has been send"));
});

const resetForgetPassword = asyncHandler(async (req, res) => {
  const { resetToken } = req.params;
  const { password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    throw new ApiError(400, "Password and Confirm Password does not match");
  }

  let hashToken = crypto.createdUser("sha256").update(resetToken).digest("hex");

  const user = await User.findOne({
    forgotPasswordToken: hashToken,
    forgotPasswordExpiry: { $gt: Date.now() },
  });

  if (!user) {
    throw new ApiError(404, "User does not exist");
  }

  user.forgotPasswordExpiry = undefined;
  user.forgotPasswordToken = undefined;

  user.password = password;
  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password has been updated"));
});

const changedCurrentPassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword, newConfirmPassword } = req.body;

  if (newPassword !== newConfirmPassword) {
    throw new ApiError(400, "Password and Confirm Password does not match");
  }

  const user = await User.findById(req.user._id);

  const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);

  if (!isPasswordCorrect) {
    throw new ApiError(400, "Old Password is incorrect");
  }

  user.password = newPassword;
  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password has been updated"));
});

export {
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
};
