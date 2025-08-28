import { User } from "../models/user.models.js";
import { ApiResponse } from "../utils/api-responses.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";
import { emailVerificationMailgenContent, sendEmail } from "../utils/mail.js";

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

export { registerUser, login, logoutUser };
