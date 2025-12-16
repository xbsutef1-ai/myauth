// ================= GLOM ULTIMATE v5 =================

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

// ================= DB =================
mongoose.connect(process.env.MONGO_URI)
  .then(()=>console.log("Mongo Connected"))
  .catch(console.error);

// ================= MODELS =================
const User = mongoose.model("User", new mongoose.Schema({
  username: String,
  password: String,
  role: { type:String, enum:["MASTER","OWNER","SOURCE","PANEL"] }
}));

const Product = mongoose.model("Product", new mongoose.Schema({
  name: String,
  authType: String,
  apiPath: String
}));

const License = mongoose.model("License", new mongoose.Schema({
  product: { type: mongoose.Schema.Types.ObjectId, ref:"Product" },
  key: String,
  username: String,
  password: String,
  hwid: String,
  status: { type:String, default:"ACTIVE" },
  expiresAt: Date,
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref:"User" }
}));

const Log = mongoose.model("Log", new mongoose.Schema({
  action: String,
  by: { type: mongoose.Schema.Types.ObjectId, ref:"User" },
  target: String,
  ip: String,
  at: { type: Date, default: Date.now }
}));

// ================= AUTO MASTER =================
(async ()=>{
  if(!await User.findOne({role:"MASTER"})){
    await User.create({
      username:"admin",
      password:await bcrypt.hash("123456",10),
      role:"MASTER"
    });
  }
})();

// ================= UTILS =================
function auth(roles=[]){
  return async (req,res,next)=>{
    try{
      const token=req.headers.authorization?.split(" ")[1];
      const user=jwt.verify(token,process.env.JWT_SECRET);
      if(roles.length && !roles.includes(user.role))
        return res.sendStatus(403);
      req.user=user;
      next();
    }catch{ res.sendStatus(401); }
  };
}

async function log(action, req, target=""){
  await Log.create({
    action,
    by:req.user?.id,
    target,
    ip:req.headers["x-forwarded-for"] || req.socket.remoteAddress
  });
}

// ================= UI =================
app.get("/",(req,res)=>res.sendFile(path.join(__dirname,"theme.html")));

// ================= AUTH =================
app.post("/auth/login", async(req,res)=>{
  const u=await User.findOne({username:req.body.username});
  if(!u || !await bcrypt.compare(req.body.password,u.password))
    return res.status(401).json({error:"Invalid"});
  const token=jwt.sign({id:u._id,role:u.role},process.env.JWT_SECRET);
  await Log.create({action:"LOGIN",by:u._id,ip:req.ip});
  res.json({token, role:u.role});
});

// ================= LICENSES =================
app.get("/licenses", auth(), async(req,res)=>{
  let q={};
  if(req.user.role==="SOURCE") q.createdBy=req.user.id;
  if(req.user.role==="PANEL") q.createdBy=req.user.id;
  res.json(await License.find(q).populate("product"));
});

// RESET HWID
app.post("/licenses/:id/reset-hwid", auth(["MASTER","OWNER","SOURCE"]), async(req,res)=>{
  const lic=await License.findById(req.params.id);
  if(!lic) return res.sendStatus(404);

  if(req.user.role==="SOURCE" && lic.createdBy.toString()!==req.user.id)
    return res.sendStatus(403);

  lic.hwid=null;
  await lic.save();
  await log("RESET_HWID",req,lic._id);
  res.json({success:true});
});

// DISABLE / ENABLE
app.post("/licenses/:id/toggle", auth(["MASTER","OWNER","SOURCE"]), async(req,res)=>{
  const lic=await License.findById(req.params.id);
  if(!lic) return res.sendStatus(404);

  if(req.user.role==="SOURCE" && lic.createdBy.toString()!==req.user.id)
    return res.sendStatus(403);

  lic.status = lic.status==="ACTIVE" ? "DISABLED" : "ACTIVE";
  await lic.save();
  await log("TOGGLE_LICENSE",req,lic._id);
  res.json({status:lic.status});
});

// DELETE (MASTER ONLY)
app.delete("/licenses/:id", auth(["MASTER"]), async(req,res)=>{
  await License.findByIdAndDelete(req.params.id);
  await log("DELETE_LICENSE",req,req.params.id);
  res.json({success:true});
});

// ================= LOGS =================
app.get("/logs", auth(["MASTER","OWNER"]), async(req,res)=>{
  res.json(await Log.find().populate("by","username role").sort({at:-1}));
});

// ================= START =================
app.listen(process.env.PORT||3000,()=>console.log("GLOM v5 RUNNING"));
