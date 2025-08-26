import express from "express";
import cors from "cors";

const app = express();

//Basic Configration
app.use(express.json({ limit: "16kb" })); //Support JSON Data
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public")); //images

//Cors Config
app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(",") || "http://localhost:5173",
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

app.get("/", (req, res) => {
  res.send("Hello");
});

export default app;
