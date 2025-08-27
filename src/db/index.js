import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config({ path: "./.env" });

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URL);
    console.log("✅MongoDB Connect");
  } catch (error) {
    console.log("❌MongoDB connection error", error);
    process.exit(1);
  }
};

export default connectDB;
