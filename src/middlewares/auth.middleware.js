import { User } from "../models/user.models.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";
import jwt from "jsonwebtoken";

const verifyJWT = asyncHandler(async (req, res, next) => {
  const token =
    req.cookies?.accessToken ||
    req.headers("Authorization")?.replace("Bearer", " ");
  //   console.log("1");

  if (!token) throw new ApiError(401, "unauthorized request");

  try {
    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    const user = await User.findById(decodedToken?._id).select(
      "-password -refreshToken -emailVerificationToken -emailVerificationExpiry",
    );
    console.log(user);
    if (!user) throw new ApiError(401, "Invalid token 1");

    req.user = user;
    next();
  } catch (error) {
    throw new ApiError(401, "Invalid token 2");
  }
});

export { verifyJWT };
