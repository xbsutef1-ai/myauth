import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* ================= DATABASE ================= */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("Mongo Connected"))
  .catch(console.error);

/* ================= MODELS ================= */
const User = mongoose.model("User", new mongoose.Schema({
  username: String,
  password: String,
  role: { type: String, enum: ["MASTER","OWNER","SOURCE","PANEL"] }
}));

const Product = mongoose.model("Product", new mongoose.Schema({
  name: String
}));

const License = mongoose.model("License", new mongoose.Schema({
  product: { type: mongoose.Schema.Types.ObjectId, ref: "Product" },
  key: String,
  hwid: String,
  status: { type: String, default: "ACTIVE" },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" }
}));

const Log = mongoose.model("Log", new mongoose.Schema({
  action: String,
  by: String,
  target: String,
  at: { type: Date, default: Date.now }
}));

/* ================= AUTO MASTER ================= */
(async () => {
  const exists = await User.findOne({ role: "MASTER" });
  if (!exists) {
    await User.create({
      username: "admin",
      password: await bcrypt.hash("123456", 10),
      role: "MASTER"
    });
    console.log("MASTER CREATED => admin / 123456");
  }
})();

/* ================= AUTH ================= */
function auth(roles = []) {
  return (req, res, next) => {
    try {
      const token = req.headers.authorization.split(" ")[1];
      const user = jwt.verify(token, process.env.JWT_SECRET);
      if (roles.length && !roles.includes(user.role)) return res.sendStatus(403);
      req.user = user;
      next();
    } catch {
      res.sendStatus(401);
    }
  };
}

/* ================= UI ================= */
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "theme.html"));
});

/* ================= LOGIN ================= */
app.post("/auth/login", async (req, res) => {
  const u = await User.findOne({ username: req.body.username });
  if (!u || !await bcrypt.compare(req.body.password, u.password))
    return res.status(401).json({ error: "Invalid" });

  const token = jwt.sign({ id: u._id, role: u.role }, process.env.JWT_SECRET);
  await Log.create({ action: "LOGIN", by: u.username });
  res.json({ token, role: u.role });
});

/* ================= LICENSES ================= */
app.get("/licenses", auth(), async (req, res) => {
  let q = {};
  if (req.user.role === "SOURCE" || req.user.role === "PANEL") {
    q.createdBy = req.user.id;
  }
  res.json(await License.find(q).populate("product"));
});

app.post("/licenses/reset/:id", auth(["MASTER","OWNER","SOURCE"]), async (req, res) => {
  const lic = await License.findById(req.params.id);
  if (!lic) return res.sendStatus(404);

  if (req.user.role === "SOURCE" && lic.createdBy.toString() !== req.user.id)
    return res.sendStatus(403);

  lic.hwid = null;
  await lic.save();
  await Log.create({ action: "RESET_HWID", by: req.user.role, target: lic._id });
  res.json({ success: true });
});

/* ================= LOGS ================= */
app.get("/logs", auth(["MASTER","OWNER"]), async (req, res) => {
  res.json(await Log.find().sort({ at: -1 }));
});

/* ================= START ================= */
app.listen(process.env.PORT || 3000, () =>
  console.log("GLOM SYSTEM RUNNING")
);
