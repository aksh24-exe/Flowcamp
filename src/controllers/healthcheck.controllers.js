import { ApiResponse } from "../utils/api-responses.js";
import { asyncHandler } from "../utils/async-handler.js";

/*
const healthCheck = async (req, res, next) => {
  try {
    const user = await getUserFromDB();
    res
      .status(200)
      .json(new ApiResponse(200, { message: "Server is Running" }));
  } catch (error) {
      next(err)
  }
};
*/

const healthCheck = asyncHandler(async (requestAnimationFrame, res) => {
  res.status(200).json(new ApiResponse(200, { message: "Server is running" }));
});

export { healthCheck };
