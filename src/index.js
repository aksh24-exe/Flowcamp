import dotenv from "dotenv";
import app from "./app.js";
import connectDB from "./db/index.js";
import { error } from "console";

dotenv.config({
  path: "./.env",
});

const PORT = process.env.PORT || 3000;

connectDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server is running on PORT http://localhost:${PORT}`);
    });
  })
  .catch(() => {
    console.error("MongoDB connection Error", error);
  });
