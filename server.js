import express from "express";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import Stripe from "stripe";
import crypto from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const config = {
  port: Number(process.env.PORT || 3000),
  nodeEnv: process.env.NODE_ENV || "development",
  appUrl: process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`,
  jwtSecret: process.env.JWT_SECRET || "",
  mailMode: (process.env.MAIL_MODE || "console").toLowerCase(),
  mailFrom: process.env.MAIL_FROM || "NOIR BLOOD <no-reply@example.com>",
  smtp: {
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE).toLowerCase() === "true",
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  },
  paymentMode: (process.env.PAYMENT_MODE || "demo").toLowerCase(),
  currency: (process.env.MARKETPLACE_CURRENCY || "usd").toLowerCase(),
  platformFeePercent: Math.max(0, Math.min(30, Number(process.env.PLATFORM_FEE_PERCENT || 5))),
  stripeSecretKey: process.env.STRIPE_SECRET_KEY || "",
  stripeWebhookSecret: process.env.STRIPE_WEBHOOK_SECRET || ""
};

if (config.jwtSecret.length < 32) {
  console.error("JWT_SECRET ต้องยาวอย่างน้อย 32 ตัวอักษร");
  process.exit(1);
}
if (!["demo","stripe"].includes(config.paymentMode)) {
  console.error("PAYMENT_MODE ต้องเป็น demo หรือ stripe");
  process.exit(1);
}
if (config.paymentMode === "stripe" && !config.stripeSecretKey) {
  console.error("PAYMENT_MODE=stripe ต้องใส่ STRIPE_SECRET_KEY");
  process.exit(1);
}

const app = express();
if (config.nodeEnv === "production") app.set("trust proxy", 1);
app.disable("x-powered-by");

const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new DatabaseSync(path.join(dataDir, "users.db"));

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    email_verified INTEGER NOT NULL DEFAULT 0,
    auth_version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS auth_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS seller_profiles (
    user_id INTEGER PRIMARY KEY,
    display_name TEXT NOT NULL DEFAULT '',
    shop_name TEXT NOT NULL DEFAULT '',
    bio TEXT NOT NULL DEFAULT '',
    avatar_url TEXT NOT NULL DEFAULT '',
    stripe_account_id TEXT,
    demo_balance INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    seller_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    image_url TEXT NOT NULL DEFAULT '',
    price_amount INTEGER NOT NULL,
    currency TEXT NOT NULL,
    stock INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(seller_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    buyer_id INTEGER,
    seller_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1,
    total_amount INTEGER NOT NULL,
    platform_fee_amount INTEGER NOT NULL DEFAULT 0,
    currency TEXT NOT NULL,
    payment_provider TEXT NOT NULL,
    provider_session_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    paid_at TEXT,
    FOREIGN KEY(buyer_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY(seller_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS withdrawals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    currency TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_payout_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_auth_tokens_hash ON auth_tokens(token_hash);
  CREATE INDEX IF NOT EXISTS idx_auth_tokens_user_type ON auth_tokens(user_id, type);
  CREATE INDEX IF NOT EXISTS idx_products_seller ON products(seller_id);
  CREATE INDEX IF NOT EXISTS idx_orders_seller ON orders(seller_id);
  CREATE INDEX IF NOT EXISTS idx_withdrawals_user ON withdrawals(user_id);
`);

function cleanUsername(v) { return typeof v === "string" ? v.trim() : ""; }
function normalizeEmail(v) { return typeof v === "string" ? v.trim().toLowerCase() : ""; }
function validUsername(v) { return /^[A-Za-z0-9_.\-ก-๙]{3,30}$/u.test(v); }
function validEmail(v) { return typeof v === "string" && v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v); }
function validPassword(v) { return typeof v === "string" && v.length >= 8 && v.length <= 72; }
function cleanText(v, max=500) { return typeof v === "string" ? v.trim().slice(0,max) : ""; }
function parseMoney(v) { const n=Number(v); return Number.isFinite(n)&&n>0 ? Math.round(n*100) : null; }

function hashToken(raw) { return crypto.createHash("sha256").update(raw).digest("hex"); }
function createDatabaseToken(userId, type, minutes) {
  const raw = crypto.randomBytes(32).toString("hex");
  db.prepare("DELETE FROM auth_tokens WHERE user_id = ? AND type = ?").run(userId, type);
  db.prepare("INSERT INTO auth_tokens (user_id, token_hash, type, expires_at) VALUES (?, ?, ?, ?)")
    .run(userId, hashToken(raw), type, Date.now()+minutes*60*1000);
  return raw;
}
function makeSessionToken(user) {
  return jwt.sign(
    { sub:String(user.id), username:user.username, av:user.auth_version },
    config.jwtSecret,
    { expiresIn:"7d", issuer:"noir-blood", audience:"noir-blood-web" }
  );
}
function setAuthCookie(res, token) {
  res.cookie("noir_session", token, {
    httpOnly:true,
    secure:config.nodeEnv==="production",
    sameSite:"strict",
    maxAge:7*24*60*60*1000,
    path:"/"
  });
}
function clearAuthCookie(res) {
  res.clearCookie("noir_session", {
    httpOnly:true,
    secure:config.nodeEnv==="production",
    sameSite:"strict",
    path:"/"
  });
}
function requireAuth(req,res,next) {
  const token=req.cookies.noir_session;
  if(!token) return res.status(401).json({error:"ยังไม่ได้เข้าสู่ระบบ"});
  try {
    const payload=jwt.verify(token,config.jwtSecret,{issuer:"noir-blood",audience:"noir-blood-web"});
    const user=db.prepare("SELECT id,username,email,email_verified,auth_version,created_at FROM users WHERE id=?").get(Number(payload.sub));
    if(!user || Number(payload.av)!==Number(user.auth_version)) {
      clearAuthCookie(res);
      return res.status(401).json({error:"Session ไม่ถูกต้อง กรุณาเข้าสู่ระบบใหม่"});
    }
    req.user=user; next();
  } catch {
    clearAuthCookie(res);
    return res.status(401).json({error:"Session หมดอายุ กรุณาเข้าสู่ระบบใหม่"});
  }
}

const transporter = config.mailMode==="smtp" ? nodemailer.createTransport({
  host:config.smtp.host,
  port:config.smtp.port,
  secure:config.smtp.secure,
  auth:config.smtp.user ? {user:config.smtp.user,pass:config.smtp.pass} : undefined
}) : null;

async function sendMail({to,subject,text,html}) {
  if(config.mailMode==="console") {
    console.log("\n========== NOIR BLOOD MAIL ==========");
    console.log("TO:",to);
    console.log("SUBJECT:",subject);
    console.log(text);
    console.log("=====================================\n");
    return;
  }
  await transporter.sendMail({from:config.mailFrom,to,subject,text,html});
}
async function sendVerificationEmail(user) {
  const token=createDatabaseToken(user.id,"verify_email",30);
  const url=`${config.appUrl}/?verify=${encodeURIComponent(token)}`;
  await sendMail({to:user.email,subject:"Verify your NOIR BLOOD email",text:`ยืนยันอีเมล: ${url}`,html:`<p><a href="${url}">Verify email</a></p>`});
}
async function sendResetPasswordEmail(user) {
  const token=createDatabaseToken(user.id,"reset_password",20);
  const url=`${config.appUrl}/?reset=${encodeURIComponent(token)}`;
  await sendMail({to:user.email,subject:"Reset your NOIR BLOOD password",text:`รีเซ็ตรหัสผ่าน: ${url}`,html:`<p><a href="${url}">Reset password</a></p>`});
}

const stripe = config.paymentMode==="stripe" ? new Stripe(config.stripeSecretKey) : null;
function ensureSellerProfile(userId) {
  db.prepare("INSERT OR IGNORE INTO seller_profiles (user_id) VALUES (?)").run(userId);
  return db.prepare("SELECT * FROM seller_profiles WHERE user_id=?").get(userId);
}
async function createSellerAccount(email) {
  return stripe.accounts.create({type:"express",email});
}
async function createSellerOnboardingLink(accountId) {
  return stripe.accountLinks.create({
    account:accountId,
    refresh_url:`${config.appUrl}/?connect=refresh`,
    return_url:`${config.appUrl}/?connect=return`,
    type:"account_onboarding"
  });
}

app.use(helmet({
  contentSecurityPolicy:{
    directives:{
      "default-src":["'self'"],
      "script-src":["'self'","'unsafe-inline'"],
      "style-src":["'self'","'unsafe-inline'"],
      "img-src":["'self'","data:","https:"],
      "connect-src":["'self'","https://api.stripe.com"],
      "object-src":["'none'"],
      "base-uri":["'self'"],
      "frame-ancestors":["'none'"]
    }
  }
}));

/* Stripe webhook ต้องอยู่ก่อน express.json */
app.post("/webhooks/stripe", express.raw({type:"application/json"}), (req,res)=>{
  if(config.paymentMode!=="stripe") return res.status(200).send("demo mode");
  if(!config.stripeWebhookSecret) return res.status(500).send("missing webhook secret");
  let event;
  try {
    event=stripe.webhooks.constructEvent(req.body,req.headers["stripe-signature"],config.stripeWebhookSecret);
  } catch(e) {
    return res.status(400).send("Invalid webhook signature");
  }
  try {
    if(event.type==="checkout.session.completed") {
      const session=event.data.object;
      const orderId=Number(session.metadata?.noir_order_id||0);
      if(orderId) {
        const order=db.prepare("SELECT * FROM orders WHERE id=?").get(orderId);
        if(order && order.status!=="paid") {
          db.exec("BEGIN");
          try {
            db.prepare("UPDATE orders SET status='paid', paid_at=CURRENT_TIMESTAMP WHERE id=?").run(orderId);
            db.prepare("UPDATE products SET stock=CASE WHEN stock>0 THEN stock-1 ELSE 0 END WHERE id=?").run(order.product_id);
            db.exec("COMMIT");
          } catch(err) { db.exec("ROLLBACK"); throw err; }
        }
      }
    }
    if(["payout.paid","payout.failed","payout.canceled"].includes(event.type)) {
      const payout=event.data.object;
      db.prepare("UPDATE withdrawals SET status=?, updated_at=CURRENT_TIMESTAMP WHERE provider_payout_id=?").run(payout.status,payout.id);
    }
    return res.json({received:true});
  } catch(e) {
    console.error(e);
    return res.status(500).send("Webhook processing failed");
  }
});

app.use(express.json({limit:"20kb"}));
app.use(cookieParser());

const authLimiter=rateLimit({windowMs:15*60*1000,limit:25,standardHeaders:"draft-8",legacyHeaders:false,message:{error:"มีคำขอมากเกินไป กรุณาลองใหม่ภายหลัง"}});

/* AUTH */
app.post("/api/auth/register",authLimiter,async(req,res)=>{
  try {
    const username=cleanUsername(req.body.username);
    const email=normalizeEmail(req.body.email);
    const password=req.body.password;
    if(!validUsername(username)) return res.status(400).json({error:"ชื่อผู้ใช้ต้องยาว 3-30 ตัวอักษร"});
    if(!validEmail(email)) return res.status(400).json({error:"รูปแบบอีเมลไม่ถูกต้อง"});
    if(!validPassword(password)) return res.status(400).json({error:"รหัสผ่านต้องยาว 8-72 ตัวอักษร"});
    const exists=db.prepare("SELECT id FROM users WHERE username=? OR email=?").get(username,email);
    if(exists) return res.status(409).json({error:"ชื่อผู้ใช้หรืออีเมลนี้ถูกใช้แล้ว"});
    const hash=await bcrypt.hash(password,12);
    const result=db.prepare("INSERT INTO users (username,email,password_hash) VALUES (?,?,?)").run(username,email,hash);
    await sendVerificationEmail({id:Number(result.lastInsertRowid),username,email});
    return res.status(201).json({ok:true,message:"สมัครสมาชิกสำเร็จ กรุณาตรวจอีเมลเพื่อยืนยันบัญชี"});
  } catch(e) { console.error(e); return res.status(500).json({error:"เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์"}); }
});

app.post("/api/auth/verify-email",authLimiter,(req,res)=>{
  const raw=typeof req.body.token==="string"?req.body.token:"";
  const rec=db.prepare("SELECT id,user_id,expires_at,used_at FROM auth_tokens WHERE token_hash=? AND type='verify_email'").get(hashToken(raw));
  if(!rec||rec.used_at||Date.now()>rec.expires_at) return res.status(400).json({error:"ลิงก์ยืนยันไม่ถูกต้องหรือหมดอายุแล้ว"});
  db.exec("BEGIN");
  try {
    db.prepare("UPDATE users SET email_verified=1 WHERE id=?").run(rec.user_id);
    db.prepare("UPDATE auth_tokens SET used_at=? WHERE id=?").run(Date.now(),rec.id);
    db.exec("COMMIT");
    return res.json({ok:true,message:"ยืนยันอีเมลสำเร็จแล้ว"});
  } catch(e) { db.exec("ROLLBACK"); return res.status(500).json({error:"เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์"}); }
});

app.post("/api/auth/login",authLimiter,async(req,res)=>{
  const identity=typeof req.body.identity==="string"?req.body.identity.trim():"";
  const password=typeof req.body.password==="string"?req.body.password:"";
  const user=db.prepare("SELECT id,username,email,password_hash,email_verified,auth_version FROM users WHERE username=? OR email=?").get(identity,identity.toLowerCase());
  if(!user || !(await bcrypt.compare(password,user.password_hash))) return res.status(401).json({error:"ชื่อผู้ใช้/อีเมล หรือรหัสผ่านไม่ถูกต้อง"});
  if(!user.email_verified) return res.status(403).json({error:"กรุณายืนยันอีเมลก่อนเข้าสู่ระบบ"});
  setAuthCookie(res,makeSessionToken(user));
  return res.json({ok:true});
});

app.post("/api/auth/forgot-password",authLimiter,async(req,res)=>{
  const email=normalizeEmail(req.body.email);
  const user=db.prepare("SELECT id,username,email FROM users WHERE email=?").get(email);
  if(user) await sendResetPasswordEmail(user);
  return res.json({ok:true,message:"ถ้าอีเมลนี้มีบัญชี ระบบจะส่งลิงก์รีเซ็ตรหัสผ่านให้"});
});

app.post("/api/auth/reset-password",authLimiter,async(req,res)=>{
  const raw=typeof req.body.token==="string"?req.body.token:"";
  const password=req.body.password;
  if(!validPassword(password)) return res.status(400).json({error:"รหัสผ่านต้องยาว 8-72 ตัวอักษร"});
  const rec=db.prepare("SELECT id,user_id,expires_at,used_at FROM auth_tokens WHERE token_hash=? AND type='reset_password'").get(hashToken(raw));
  if(!rec||rec.used_at||Date.now()>rec.expires_at) return res.status(400).json({error:"ลิงก์รีเซ็ตไม่ถูกต้องหรือหมดอายุแล้ว"});
  const hash=await bcrypt.hash(password,12);
  db.exec("BEGIN");
  try {
    db.prepare("UPDATE users SET password_hash=?, auth_version=auth_version+1 WHERE id=?").run(hash,rec.user_id);
    db.prepare("UPDATE auth_tokens SET used_at=? WHERE id=?").run(Date.now(),rec.id);
    db.exec("COMMIT");
    clearAuthCookie(res);
    return res.json({ok:true,message:"เปลี่ยนรหัสผ่านสำเร็จ กรุณาเข้าสู่ระบบใหม่"});
  } catch(e) { db.exec("ROLLBACK"); return res.status(500).json({error:"เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์"}); }
});

app.post("/api/auth/logout",(req,res)=>{ clearAuthCookie(res); return res.json({ok:true}); });

/* USER */
app.get("/api/me",requireAuth,(req,res)=>res.json({user:{id:req.user.id,username:req.user.username,email:req.user.email,createdAt:req.user.created_at}}));

/* MARKET */
app.get("/api/market/products",requireAuth,(req,res)=>{
  const products=db.prepare(`
    SELECT p.id,p.seller_id,p.name,p.description,p.image_url,p.price_amount,p.currency,p.stock,p.active,p.created_at,
      COALESCE(NULLIF(sp.shop_name,''),u.username) AS shop_name
    FROM products p
    JOIN users u ON u.id=p.seller_id
    LEFT JOIN seller_profiles sp ON sp.user_id=p.seller_id
    WHERE p.active=1 AND p.stock>0
    ORDER BY p.id DESC
  `).all();
  res.json({products,currentUserId:req.user.id,currency:config.currency});
});

app.get("/api/seller/profile",requireAuth,(req,res)=>{
  const p=ensureSellerProfile(req.user.id);
  res.json({profile:{displayName:p.display_name,shopName:p.shop_name,bio:p.bio,avatarUrl:p.avatar_url}});
});

app.put("/api/seller/profile",requireAuth,(req,res)=>{
  ensureSellerProfile(req.user.id);
  const displayName=cleanText(req.body.displayName,80), shopName=cleanText(req.body.shopName,80), bio=cleanText(req.body.bio,700), avatarUrl=cleanText(req.body.avatarUrl,1000);
  if(avatarUrl && !/^https?:\/\//i.test(avatarUrl)) return res.status(400).json({error:"Avatar URL ต้องขึ้นต้นด้วย http:// หรือ https://"});
  db.prepare("UPDATE seller_profiles SET display_name=?,shop_name=?,bio=?,avatar_url=?,updated_at=CURRENT_TIMESTAMP WHERE user_id=?")
    .run(displayName,shopName,bio,avatarUrl,req.user.id);
  res.json({ok:true});
});

app.get("/api/seller/products",requireAuth,(req,res)=>res.json({products:db.prepare("SELECT * FROM products WHERE seller_id=? ORDER BY id DESC").all(req.user.id)}));

app.post("/api/seller/products",requireAuth,(req,res)=>{
  const name=cleanText(req.body.name,120),description=cleanText(req.body.description,1000),imageUrl=cleanText(req.body.imageUrl,1000),priceAmount=parseMoney(req.body.price),stock=Math.max(0,Math.floor(Number(req.body.stock||0)));
  if(!name) return res.status(400).json({error:"กรุณาใส่ชื่อสินค้า"});
  if(!priceAmount) return res.status(400).json({error:"ราคาสินค้าไม่ถูกต้อง"});
  const r=db.prepare("INSERT INTO products (seller_id,name,description,image_url,price_amount,currency,stock) VALUES (?,?,?,?,?,?,?)")
    .run(req.user.id,name,description,imageUrl,priceAmount,config.currency,stock);
  res.status(201).json({ok:true,productId:Number(r.lastInsertRowid)});
});

app.delete("/api/seller/products/:id",requireAuth,(req,res)=>{
  db.prepare("UPDATE products SET active=0,updated_at=CURRENT_TIMESTAMP WHERE id=? AND seller_id=?").run(Number(req.params.id),req.user.id);
  res.json({ok:true});
});

app.get("/api/seller/connect-status",requireAuth,async(req,res)=>{
  const p=ensureSellerProfile(req.user.id);
  if(config.paymentMode==="demo") return res.json({mode:"demo",connected:true,payoutsEnabled:true,chargesEnabled:true});
  if(!p.stripe_account_id) return res.json({mode:"stripe",connected:false,payoutsEnabled:false,chargesEnabled:false});
  const acc=await stripe.accounts.retrieve(p.stripe_account_id);
  res.json({mode:"stripe",connected:Boolean(acc.details_submitted),payoutsEnabled:Boolean(acc.payouts_enabled),chargesEnabled:Boolean(acc.charges_enabled)});
});

app.post("/api/seller/connect-account",requireAuth,async(req,res)=>{
  const p=ensureSellerProfile(req.user.id);
  if(config.paymentMode==="demo") return res.json({ok:true,demo:true,message:"โหมด demo: ถือว่าผูกบัญชีรับเงินแล้ว"});
  let accountId=p.stripe_account_id;
  if(!accountId) {
    const acc=await createSellerAccount(req.user.email);
    accountId=acc.id;
    db.prepare("UPDATE seller_profiles SET stripe_account_id=? WHERE user_id=?").run(accountId,req.user.id);
  }
  const link=await createSellerOnboardingLink(accountId);
  res.json({ok:true,url:link.url});
});

app.get("/api/seller/wallet",requireAuth,async(req,res)=>{
  const p=ensureSellerProfile(req.user.id);
  if(config.paymentMode==="demo") return res.json({mode:"demo",currency:config.currency,available:p.demo_balance,pending:0});
  if(!p.stripe_account_id) return res.json({mode:"stripe",currency:config.currency,available:0,pending:0,needsOnboarding:true});
  const b=await stripe.balance.retrieve({},{stripeAccount:p.stripe_account_id});
  const sum=(list)=>list.filter(x=>x.currency===config.currency).reduce((s,x)=>s+x.amount,0);
  res.json({mode:"stripe",currency:config.currency,available:sum(b.available),pending:sum(b.pending)});
});

app.post("/api/market/checkout/:productId",requireAuth,async(req,res)=>{
  const product=db.prepare("SELECT p.*,sp.stripe_account_id FROM products p LEFT JOIN seller_profiles sp ON sp.user_id=p.seller_id WHERE p.id=? AND p.active=1").get(Number(req.params.productId));
  if(!product||product.stock<=0) return res.status(404).json({error:"สินค้านี้ไม่มีจำหน่ายแล้ว"});
  if(product.seller_id===req.user.id) return res.status(400).json({error:"ไม่สามารถซื้อสินค้าของตัวเองได้"});
  const fee=Math.round(product.price_amount*(config.platformFeePercent/100));
  const r=db.prepare("INSERT INTO orders (buyer_id,seller_id,product_id,quantity,total_amount,platform_fee_amount,currency,payment_provider,status) VALUES (?,?,?,1,?,?,?,?, 'pending')")
    .run(req.user.id,product.seller_id,product.id,product.price_amount,fee,product.currency,config.paymentMode);
  const orderId=Number(r.lastInsertRowid);

  if(config.paymentMode==="demo") {
    db.exec("BEGIN");
    try {
      db.prepare("UPDATE orders SET status='paid',paid_at=CURRENT_TIMESTAMP WHERE id=?").run(orderId);
      db.prepare("UPDATE products SET stock=stock-1 WHERE id=? AND stock>0").run(product.id);
      db.prepare("INSERT OR IGNORE INTO seller_profiles (user_id) VALUES (?)").run(product.seller_id);
      db.prepare("UPDATE seller_profiles SET demo_balance=demo_balance+? WHERE user_id=?").run(product.price_amount-fee,product.seller_id);
      db.exec("COMMIT");
      return res.json({ok:true,demo:true,message:"ซื้อสินค้าในโหมด demo สำเร็จ"});
    } catch(e) { db.exec("ROLLBACK"); throw e; }
  }

  if(!product.stripe_account_id) return res.status(400).json({error:"ผู้ขายยังไม่ได้ผูกบัญชีรับเงิน"});
  const account=await stripe.accounts.retrieve(product.stripe_account_id);
  if(!account.charges_enabled) return res.status(400).json({error:"บัญชีผู้ขายยังไม่พร้อมรับชำระเงิน"});
  const session=await stripe.checkout.sessions.create({
    mode:"payment",
    line_items:[{quantity:1,price_data:{currency:product.currency,unit_amount:product.price_amount,product_data:{name:product.name,description:product.description||undefined,images:product.image_url?[product.image_url]:undefined}}}],
    payment_intent_data:{application_fee_amount:fee,transfer_data:{destination:product.stripe_account_id},metadata:{noir_order_id:String(orderId)}},
    metadata:{noir_order_id:String(orderId)},
    success_url:`${config.appUrl}/?checkout=success`,
    cancel_url:`${config.appUrl}/?checkout=cancel`
  });
  db.prepare("UPDATE orders SET provider_session_id=? WHERE id=?").run(session.id,orderId);
  res.json({ok:true,url:session.url});
});

app.get("/api/seller/orders",requireAuth,(req,res)=>{
  const orders=db.prepare(`
    SELECT o.id,o.total_amount,o.platform_fee_amount,o.currency,o.status,o.created_at,o.paid_at,p.name AS product_name,u.username AS buyer_username
    FROM orders o JOIN products p ON p.id=o.product_id LEFT JOIN users u ON u.id=o.buyer_id
    WHERE o.seller_id=? ORDER BY o.id DESC
  `).all(req.user.id);
  res.json({orders});
});

app.get("/api/seller/withdrawals",requireAuth,(req,res)=>res.json({withdrawals:db.prepare("SELECT * FROM withdrawals WHERE user_id=? ORDER BY id DESC").all(req.user.id)}));

app.post("/api/seller/withdrawals",requireAuth,async(req,res)=>{
  const amount=parseMoney(req.body.amount);
  if(!amount) return res.status(400).json({error:"จำนวนเงินที่ถอนต้องมากกว่า 0"});
  const p=ensureSellerProfile(req.user.id);

  if(config.paymentMode==="demo") {
    if(p.demo_balance<amount) return res.status(400).json({error:"ยอดคงเหลือไม่เพียงพอ"});
    db.exec("BEGIN");
    try {
      db.prepare("UPDATE seller_profiles SET demo_balance=demo_balance-? WHERE user_id=?").run(amount,req.user.id);
      const r=db.prepare("INSERT INTO withdrawals (user_id,amount,currency,provider,status,note) VALUES (?,?,?,'demo','paid','Demo payout')")
        .run(req.user.id,amount,config.currency);
      db.exec("COMMIT");
      return res.json({ok:true,withdrawalId:Number(r.lastInsertRowid),message:"ถอนเงินในโหมด demo สำเร็จ"});
    } catch(e) { db.exec("ROLLBACK"); throw e; }
  }

  if(!p.stripe_account_id) return res.status(400).json({error:"กรุณาผูกบัญชีรับเงินก่อน"});
  const payout=await stripe.payouts.create({amount,currency:config.currency,method:"standard",description:"NOIR BLOOD seller withdrawal"},{stripeAccount:p.stripe_account_id});
  const r=db.prepare("INSERT INTO withdrawals (user_id,amount,currency,provider,provider_payout_id,status,note) VALUES (?,?,?,'stripe',?,?,?)")
    .run(req.user.id,amount,config.currency,payout.id,payout.status,"Standard payout");
  res.json({ok:true,withdrawalId:Number(r.lastInsertRowid),status:payout.status,message:"ส่งคำขอถอนเงินแล้ว"});
});

app.get("/api/health",(req,res)=>res.json({ok:true,app:"NOIR BLOOD Single File",version:"5.0.0"}));

const PAGE = `<!DOCTYPE html>
<html lang="th">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NOIR BLOOD MARKET</title>
  <style>
:root{
  --bg:#050506;--panel:#0d0d10;--panel2:#121216;--red:#b51f42;--red2:#681025;
  --text:#f5f5f6;--muted:#8a8a91;--line:rgba(181,31,66,.23);--green:#6ee7a0
}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;font-family:Arial,Helvetica,sans-serif;color:var(--text);
background:radial-gradient(circle at 15% 10%,rgba(130,10,40,.18),transparent 34%),radial-gradient(circle at 85% 85%,rgba(90,5,30,.2),transparent 35%),var(--bg)}
button,input,textarea{font:inherit}button{cursor:pointer}.hidden{display:none!important}
.glow{position:fixed;border-radius:50%;filter:blur(110px);pointer-events:none;z-index:-1}
.glow-one{width:380px;height:380px;top:-150px;left:-120px;background:#8b1531;opacity:.3}
.glow-two{width:420px;height:420px;right:-160px;bottom:-180px;background:#4d0a1b;opacity:.35}
nav{position:fixed;inset:0 0 auto 0;height:74px;padding:0 5%;display:flex;align-items:center;justify-content:space-between;background:rgba(5,5,6,.84);backdrop-filter:blur(18px);border-bottom:1px solid var(--line);z-index:20}
.brand{display:flex;align-items:center;gap:12px;border:0;background:none;color:#fff;font-weight:900;letter-spacing:3px}.brand>span:last-child{color:var(--red)}
.logo-mark{width:32px;height:32px;border:1px solid var(--red);border-radius:8px;transform:rotate(45deg);box-shadow:0 0 18px rgba(181,31,66,.4)}
.nav-actions{display:flex;gap:6px;align-items:center}.nav-actions button{border:0;background:transparent;color:#aaa;padding:10px}.nav-actions button:hover{color:#fff}.danger-link{color:#ff6b82!important}
main{min-height:100vh;padding:105px 5% 55px;max-width:1500px;margin:auto}
.auth-shell{min-height:calc(100vh - 160px);display:grid;grid-template-columns:1fr 430px;gap:70px;align-items:center}
.eyebrow{color:var(--red);font-size:11px;letter-spacing:4px;font-weight:800}.hero-copy h1{font-size:clamp(64px,9vw,112px);line-height:.84;letter-spacing:-7px;margin:17px 0 28px}.hero-copy h1 span{color:var(--red);text-shadow:0 0 34px rgba(181,31,66,.28)}
.lead,.muted{color:var(--muted);line-height:1.7}.panel{padding:30px;border:1px solid var(--line);border-radius:22px;background:linear-gradient(145deg,rgba(20,20,24,.96),rgba(7,7,9,.97));box-shadow:0 26px 70px rgba(0,0,0,.45)}
.auth-view,.dash-page{display:none}.auth-view.active,.dash-page.active{display:block;animation:enter .22s ease}@keyframes enter{from{opacity:0;transform:translateY(8px)}}
h1,h2,h3,p{margin-top:0}h2{font-size:28px;margin-bottom:8px}.subtitle{color:var(--muted);font-size:13px;margin-bottom:24px}
form{display:grid;gap:14px}label{display:grid;gap:8px;color:#aaa;font-size:12px}input,textarea{width:100%;border:1px solid #29292f;border-radius:10px;background:#09090b;color:#fff;padding:0 14px;outline:none}
input{height:50px}textarea{min-height:105px;padding-top:12px;resize:vertical}input:focus,textarea:focus{border-color:var(--red);box-shadow:0 0 0 4px rgba(181,31,66,.08)}
.primary,.secondary{min-height:48px;border-radius:10px;font-weight:800}.primary{border:0;color:#fff;background:linear-gradient(135deg,#5b0b1e,#a81a3a)}.secondary{border:1px solid var(--line);color:#fff;background:rgba(181,31,66,.1)}.compact{min-height:38px;padding:0 14px}.switch{text-align:center;color:#777;font-size:13px;margin-top:18px}.text-button{border:0;background:none;color:#e02d58}
.message{display:none;margin:14px 0;padding:12px;border-radius:9px;font-size:13px}.message.show{display:block}.message.error{color:#ff7085;background:rgba(255,70,100,.07);border:1px solid rgba(255,70,100,.16)}.message.success{color:#78e1a0;background:rgba(70,220,120,.06);border:1px solid rgba(70,220,120,.15)}
.dash-header{display:flex;justify-content:space-between;gap:20px;align-items:center;margin-bottom:30px}.dash-header h1{font-size:44px;margin:5px 0}.mini-user{display:flex;align-items:center;gap:12px}.mini-user small{display:block;color:#777;margin-top:3px}
.avatar-small,.avatar-img{width:46px;height:46px;border-radius:50%;object-fit:cover}.avatar-small{display:grid;place-items:center;background:linear-gradient(135deg,#8e1834,#350711);font-weight:900}
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:28px}.stat-card{padding:22px;border:1px solid #1d1d22;border-radius:16px;background:#0b0b0e}.stat-card span{display:block;color:#777;font-size:11px;letter-spacing:1px}.stat-card strong{display:block;margin-top:12px;font-size:25px}.stat-card.big{grid-column:span 2}.section-head{display:flex;align-items:end;justify-content:space-between;gap:15px;margin:28px 0 16px}.section-head h2{margin:5px 0 0}
.product-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:18px}.product-card{overflow:hidden;border:1px solid #1d1d22;border-radius:16px;background:#0b0b0e}.product-card img,.product-placeholder{width:100%;height:200px;object-fit:cover}.product-placeholder{display:grid;place-items:center;background:linear-gradient(135deg,#17171c,#310912);color:#777;font-size:32px}.product-body{padding:18px}.product-body h3{margin-bottom:8px}.product-body .shop{font-size:12px;color:var(--red)}.product-footer{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-top:18px}.price{font-size:20px;font-weight:900}.buy-button{border:1px solid var(--line);background:rgba(181,31,66,.12);color:#fff;border-radius:9px;padding:9px 13px}
.two-col{display:grid;grid-template-columns:1fr 1.2fr;gap:22px}.form-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}.stack-list{display:grid;gap:12px}.list-card{display:flex;gap:14px;align-items:center;padding:14px;border:1px solid #1d1d22;border-radius:13px;background:#0b0b0e}.list-card img,.list-thumb{width:70px;height:70px;border-radius:10px;object-fit:cover}.list-thumb{display:grid;place-items:center;background:#18181d;color:#777}.list-info{flex:1}.list-info strong{display:block;margin-bottom:5px}.list-info small{color:#777}.list-actions{display:flex;gap:8px}.mini-btn{border:1px solid var(--line);background:transparent;color:#ddd;border-radius:8px;padding:8px 10px}
.table-wrap{overflow:auto;border:1px solid #1d1d22;border-radius:14px}table{width:100%;border-collapse:collapse;background:#0a0a0d}th,td{text-align:left;padding:14px;border-bottom:1px solid #19191d;font-size:13px}th{color:#777;font-size:11px;letter-spacing:1px}.status-paid{color:var(--green)}.status-pending,.status-in_transit{color:#e8bd63}.status-failed,.status-canceled{color:#ff7085}
.profile-preview{text-align:center}.profile-photo{width:130px;height:130px;border-radius:50%;object-fit:cover;margin:0 auto 20px}.profile-photo.fallback{display:grid;place-items:center;background:linear-gradient(135deg,#8e1834,#350711);font-size:42px;font-weight:900}.red-text{color:var(--red)}.tiny-note{font-size:11px;color:#6f6f76;line-height:1.6;margin-top:15px}
@media(max-width:1050px){.product-grid{grid-template-columns:repeat(2,1fr)}.stats-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:850px){.auth-shell{grid-template-columns:1fr;max-width:560px;margin:auto}.hero-copy{text-align:center}.two-col{grid-template-columns:1fr}.product-grid{grid-template-columns:1fr 1fr}}
@media(max-width:650px){nav{padding:0 16px}.nav-actions button{font-size:11px;padding:7px 5px}.brand{font-size:12px;letter-spacing:1px}.logo-mark{width:25px;height:25px}main{padding:95px 16px 35px}.hero-copy h1{font-size:54px;letter-spacing:-4px}.dash-header{align-items:flex-start;flex-direction:column}.stats-grid,.product-grid{grid-template-columns:1fr}.stat-card.big{grid-column:span 1}.form-row{grid-template-columns:1fr}.mini-user{width:100%}}

</style>
</head>
<body>
  <div class="glow glow-one"></div>
  <div class="glow glow-two"></div>

  <nav id="topNav">
    <button class="brand" data-auth-view="login">
      <span class="logo-mark"></span>
      NOIR<span>BLOOD</span>
    </button>

    <div id="guestNav" class="nav-actions">
      <button data-auth-view="login">LOGIN</button>
      <button data-auth-view="register">REGISTER</button>
    </div>

    <div id="userNav" class="nav-actions hidden">
      <button data-page="home">HOME</button>
      <button data-page="products">สินค้า</button>
      <button data-page="wallet">กระเป๋าเงิน</button>
      <button data-page="withdrawals">ประวัติถอน</button>
      <button data-page="profile">โปรไฟล์</button>
      <button id="logoutButton" class="danger-link">LOGOUT</button>
    </div>
  </nav>

  <main>
    <!-- AUTH -->
    <section id="authShell" class="auth-shell">
      <div class="hero-copy">
        <p class="eyebrow">PRIVATE MARKETPLACE / SECURE AUTH</p>
        <h1>NOIR<br><span>MARKET.</span></h1>
        <p class="lead">
          ร้านค้าออนไลน์โทนดำตัดแดงเลือดหมู
          พร้อมระบบสินค้า การชำระเงิน บัญชีรับเงิน ถอนเงิน และโปรไฟล์ผู้ขาย
        </p>
      </div>

      <section class="panel">
        <div id="loginView" class="auth-view active">
          <p class="eyebrow">ACCESS</p>
          <h2>Login</h2>
          <p class="subtitle">เข้าสู่ระบบด้วย Username หรือ Email</p>
          <form id="loginForm">
            <label>Username / Email
              <input id="loginIdentity" autocomplete="username" required>
            </label>
            <label>Password
              <input id="loginPassword" type="password" autocomplete="current-password" required maxlength="72">
            </label>
            <button class="primary">LOGIN</button>
          </form>
          <p class="switch"><button class="text-button" data-auth-view="forgot">ลืมรหัสผ่าน?</button></p>
          <p class="switch">ยังไม่มีบัญชี? <button class="text-button" data-auth-view="register">สมัครสมาชิก</button></p>
        </div>

        <div id="registerView" class="auth-view">
          <p class="eyebrow">NEW IDENTITY</p>
          <h2>Register</h2>
          <p class="subtitle">สร้างบัญชีใหม่</p>
          <form id="registerForm">
            <label>Username<input id="registerUsername" required minlength="3" maxlength="30"></label>
            <label>Email<input id="registerEmail" type="email" required></label>
            <label>Password<input id="registerPassword" type="password" required minlength="8" maxlength="72"></label>
            <label>Confirm Password<input id="registerConfirm" type="password" required minlength="8" maxlength="72"></label>
            <button class="primary">CREATE ACCOUNT</button>
          </form>
          <p class="switch">มีบัญชีแล้ว? <button class="text-button" data-auth-view="login">Login</button></p>
        </div>

        <div id="forgotView" class="auth-view">
          <p class="eyebrow">RECOVERY</p>
          <h2>Forgot Password</h2>
          <form id="forgotForm">
            <label>Email<input id="forgotEmail" type="email" required></label>
            <button class="primary">SEND RESET LINK</button>
          </form>
          <p class="switch"><button class="text-button" data-auth-view="login">กลับหน้า Login</button></p>
        </div>

        <div id="verifyView" class="auth-view">
          <p class="eyebrow">VERIFY EMAIL</p>
          <h2>Confirm Email</h2>
          <p class="subtitle">กำลังตรวจสอบลิงก์ยืนยันอีเมล</p>
          <button class="secondary" data-auth-view="login">กลับหน้า Login</button>
        </div>

        <div id="resetView" class="auth-view">
          <p class="eyebrow">NEW PASSWORD</p>
          <h2>Reset Password</h2>
          <form id="resetForm">
            <label>New Password<input id="resetPassword" type="password" minlength="8" maxlength="72" required></label>
            <label>Confirm Password<input id="resetConfirm" type="password" minlength="8" maxlength="72" required></label>
            <button class="primary">CHANGE PASSWORD</button>
          </form>
        </div>

        <div id="authMessage" class="message"></div>
      </section>
    </section>

    <!-- DASHBOARD -->
    <section id="dashboard" class="dashboard hidden">
      <header class="dash-header">
        <div>
          <p class="eyebrow">SELLER DASHBOARD</p>
          <h1 id="dashboardTitle">HOME</h1>
        </div>
        <div class="mini-user">
          <img id="navAvatar" alt="" class="avatar-img hidden">
          <div id="navAvatarFallback" class="avatar-small">?</div>
          <div>
            <strong id="navUsername">USER</strong>
            <small id="navEmail">-</small>
          </div>
        </div>
      </header>

      <div id="pageMessage" class="message"></div>

      <section id="homePage" class="dash-page active">
        <div class="stats-grid">
          <div class="stat-card"><span>AVAILABLE</span><strong id="homeBalance">$0.00</strong></div>
          <div class="stat-card"><span>MY PRODUCTS</span><strong id="homeProductCount">0</strong></div>
          <div class="stat-card"><span>SALES</span><strong id="homeSalesCount">0</strong></div>
          <div class="stat-card"><span>PAYOUT ACCOUNT</span><strong id="homePayoutStatus">DEMO</strong></div>
        </div>

        <div class="section-head">
          <div><p class="eyebrow">MARKET</p><h2>สินค้าในตลาด</h2></div>
          <button class="secondary compact" data-page="products">+ เพิ่มสินค้า</button>
        </div>
        <div id="marketGrid" class="product-grid"></div>
      </section>

      <section id="productsPage" class="dash-page">
        <div class="two-col">
          <div class="panel">
            <p class="eyebrow">NEW PRODUCT</p>
            <h2>เพิ่มสินค้า</h2>
            <form id="productForm">
              <label>ชื่อสินค้า<input id="productName" required maxlength="120"></label>
              <label>รายละเอียด<textarea id="productDescription" maxlength="1000"></textarea></label>
              <label>URL รูปสินค้า<input id="productImage" placeholder="https://..."></label>
              <div class="form-row">
                <label>ราคา<input id="productPrice" type="number" step="0.01" min="0.01" required></label>
                <label>จำนวน<input id="productStock" type="number" min="0" step="1" value="1" required></label>
              </div>
              <button class="primary">ADD PRODUCT</button>
            </form>
          </div>

          <div>
            <div class="section-head"><div><p class="eyebrow">INVENTORY</p><h2>สินค้าของฉัน</h2></div></div>
            <div id="sellerProducts" class="stack-list"></div>
          </div>
        </div>
      </section>

      <section id="walletPage" class="dash-page">
        <div class="stats-grid">
          <div class="stat-card big"><span>ยอดถอนได้</span><strong id="walletAvailable">$0.00</strong></div>
          <div class="stat-card big"><span>ยอดรอดำเนินการ</span><strong id="walletPending">$0.00</strong></div>
        </div>

        <div class="two-col">
          <div class="panel">
            <p class="eyebrow">PAYOUT ACCOUNT</p>
            <h2>บัญชีรับเงิน</h2>
            <p id="connectText" class="muted">กำลังตรวจสอบ...</p>
            <button id="connectButton" class="primary">ผูกบัญชีรับเงิน</button>
          </div>

          <div class="panel">
            <p class="eyebrow">WITHDRAW</p>
            <h2>ถอนเงิน</h2>
            <form id="withdrawForm">
              <label>จำนวนเงิน<input id="withdrawAmount" type="number" step="0.01" min="0.01" required></label>
              <button class="primary">WITHDRAW</button>
            </form>
            <p class="tiny-note">โหมด Stripe จะส่ง payout ไปยังบัญชีภายนอกที่ผูกผ่าน Stripe Connect</p>
          </div>
        </div>
      </section>

      <section id="withdrawalsPage" class="dash-page">
        <div class="section-head"><div><p class="eyebrow">HISTORY</p><h2>ประวัติการถอน</h2></div></div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>ID</th><th>จำนวน</th><th>สถานะ</th><th>ระบบ</th><th>วันที่</th></tr></thead>
            <tbody id="withdrawalRows"></tbody>
          </table>
        </div>
      </section>

      <section id="profilePage" class="dash-page">
        <div class="two-col">
          <div class="panel profile-preview">
            <img id="profilePreviewImage" class="profile-photo hidden" alt="">
            <div id="profilePreviewFallback" class="profile-photo fallback">?</div>
            <h2 id="profilePreviewName">USER</h2>
            <p id="profilePreviewShop" class="red-text">NOIR SHOP</p>
            <p id="profilePreviewBio" class="muted">ยังไม่มีรายละเอียดร้าน</p>
          </div>

          <div class="panel">
            <p class="eyebrow">SELLER PROFILE</p>
            <h2>แก้ไขโปรไฟล์</h2>
            <form id="sellerProfileForm">
              <label>ชื่อที่แสดง<input id="displayName" maxlength="80"></label>
              <label>ชื่อร้าน<input id="shopName" maxlength="80"></label>
              <label>รายละเอียดร้าน<textarea id="shopBio" maxlength="700"></textarea></label>
              <label>URL รูปโปรไฟล์<input id="avatarUrl" placeholder="https://..."></label>
              <button class="primary">SAVE PROFILE</button>
            </form>
          </div>
        </div>
      </section>
    </section>
  </main>

  <script>
const money = (cents, currency = "usd") =>
  new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currency.toUpperCase()
  }).format((Number(cents) || 0) / 100);

const authViews = {
  login: document.getElementById("loginView"),
  register: document.getElementById("registerView"),
  forgot: document.getElementById("forgotView"),
  verify: document.getElementById("verifyView"),
  reset: document.getElementById("resetView")
};

const pages = {
  home: document.getElementById("homePage"),
  products: document.getElementById("productsPage"),
  wallet: document.getElementById("walletPage"),
  withdrawals: document.getElementById("withdrawalsPage"),
  profile: document.getElementById("profilePage")
};

const authMessage = document.getElementById("authMessage");
const pageMessage = document.getElementById("pageMessage");

let currentUser = null;
let resetToken = "";
let currency = "usd";

async function api(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    },
    ...options
  });

  let data = {};
  try { data = await response.json(); } catch {}

  if (!response.ok) {
    throw new Error(data.error || "เกิดข้อผิดพลาด");
  }

  return data;
}

function setMessage(element, text, type = "error") {
  element.textContent = text;
  element.className = \`message show \${type}\`;
}

function clearMessage(element) {
  element.textContent = "";
  element.className = "message";
}

function showAuthView(name) {
  Object.values(authViews).forEach((view) => view.classList.remove("active"));
  authViews[name].classList.add("active");
  clearMessage(authMessage);
}

function showPage(name) {
  Object.values(pages).forEach((page) => page.classList.remove("active"));
  pages[name].classList.add("active");
  document.getElementById("dashboardTitle").textContent = name.toUpperCase();
  clearMessage(pageMessage);

  if (name === "home") loadHome();
  if (name === "products") loadSellerProducts();
  if (name === "wallet") loadWallet();
  if (name === "withdrawals") loadWithdrawals();
  if (name === "profile") loadSellerProfile();
}

function enterDashboard(user) {
  currentUser = user;

  document.getElementById("authShell").classList.add("hidden");
  document.getElementById("dashboard").classList.remove("hidden");
  document.getElementById("guestNav").classList.add("hidden");
  document.getElementById("userNav").classList.remove("hidden");

  document.getElementById("navUsername").textContent = user.username;
  document.getElementById("navEmail").textContent = user.email;
  document.getElementById("navAvatarFallback").textContent =
    user.username.charAt(0).toUpperCase();

  showPage("home");
}

function leaveDashboard() {
  currentUser = null;
  document.getElementById("dashboard").classList.add("hidden");
  document.getElementById("authShell").classList.remove("hidden");
  document.getElementById("guestNav").classList.remove("hidden");
  document.getElementById("userNav").classList.add("hidden");
  showAuthView("login");
}

async function loadMe() {
  try {
    const data = await api("/api/me");
    enterDashboard(data.user);
    return true;
  } catch {
    return false;
  }
}

/* AUTH */
document.querySelectorAll("[data-auth-view]").forEach((button) => {
  button.addEventListener("click", () => {
    document.getElementById("authShell").classList.remove("hidden");
    showAuthView(button.dataset.authView);
  });
});

document.querySelectorAll("[data-page]").forEach((button) => {
  button.addEventListener("click", () => showPage(button.dataset.page));
});

document.getElementById("loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        identity: document.getElementById("loginIdentity").value.trim(),
        password: document.getElementById("loginPassword").value
      })
    });
    document.getElementById("loginPassword").value = "";
    await loadMe();
  } catch (error) {
    setMessage(authMessage, error.message);
  }
});

document.getElementById("registerForm").addEventListener("submit", async (event) => {
  event.preventDefault();

  const password = document.getElementById("registerPassword").value;
  const confirm = document.getElementById("registerConfirm").value;

  if (password !== confirm) {
    setMessage(authMessage, "รหัสผ่านไม่ตรงกัน");
    return;
  }

  try {
    const data = await api("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({
        username: document.getElementById("registerUsername").value.trim(),
        email: document.getElementById("registerEmail").value.trim(),
        password
      })
    });

    setMessage(authMessage, data.message, "success");
  } catch (error) {
    setMessage(authMessage, error.message);
  }
});

document.getElementById("forgotForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const data = await api("/api/auth/forgot-password", {
      method: "POST",
      body: JSON.stringify({
        email: document.getElementById("forgotEmail").value.trim()
      })
    });
    setMessage(authMessage, data.message, "success");
  } catch (error) {
    setMessage(authMessage, error.message);
  }
});

document.getElementById("resetForm").addEventListener("submit", async (event) => {
  event.preventDefault();

  const password = document.getElementById("resetPassword").value;
  const confirm = document.getElementById("resetConfirm").value;

  if (password !== confirm) {
    setMessage(authMessage, "รหัสผ่านไม่ตรงกัน");
    return;
  }

  try {
    const data = await api("/api/auth/reset-password", {
      method: "POST",
      body: JSON.stringify({ token: resetToken, password })
    });

    setMessage(authMessage, data.message, "success");
    setTimeout(() => showAuthView("login"), 1000);
  } catch (error) {
    setMessage(authMessage, error.message);
  }
});

document.getElementById("logoutButton").addEventListener("click", async () => {
  try {
    await api("/api/auth/logout", { method: "POST", body: "{}" });
  } finally {
    leaveDashboard();
  }
});

/* HOME / MARKET */
async function loadHome() {
  try {
    const [market, wallet, myProducts, orders, connect] = await Promise.all([
      api("/api/market/products"),
      api("/api/seller/wallet"),
      api("/api/seller/products"),
      api("/api/seller/orders"),
      api("/api/seller/connect-status")
    ]);

    currency = market.currency || wallet.currency || "usd";

    document.getElementById("homeBalance").textContent =
      money(wallet.available, wallet.currency);

    document.getElementById("homeProductCount").textContent =
      myProducts.products.length;

    document.getElementById("homeSalesCount").textContent =
      orders.orders.filter((o) => o.status === "paid").length;

    document.getElementById("homePayoutStatus").textContent =
      connect.mode === "demo"
        ? "DEMO"
        : connect.payoutsEnabled
          ? "READY"
          : connect.connected
            ? "VERIFYING"
            : "NOT LINKED";

    const grid = document.getElementById("marketGrid");
    grid.innerHTML = "";

    if (!market.products.length) {
      grid.innerHTML = \`<p class="muted">ยังไม่มีสินค้าในตลาด</p>\`;
      return;
    }

    market.products.forEach((product) => {
      const card = document.createElement("article");
      card.className = "product-card";

      const media = product.image_url
        ? \`<img src="\${escapeHtml(product.image_url)}" alt="">\`
        : \`<div class="product-placeholder">◆</div>\`;

      const own = product.seller_id === market.currentUserId;

      card.innerHTML = \`
        \${media}
        <div class="product-body">
          <div class="shop">\${escapeHtml(product.shop_name)}</div>
          <h3>\${escapeHtml(product.name)}</h3>
          <p class="muted">\${escapeHtml(product.description || "")}</p>
          <div class="product-footer">
            <span class="price">\${money(product.price_amount, product.currency)}</span>
            <button class="buy-button" \${own ? "disabled" : ""}>
              \${own ? "สินค้าของคุณ" : "ซื้อ"}
            </button>
          </div>
        </div>
      \`;

      if (!own) {
        card.querySelector(".buy-button").addEventListener("click", () => {
          checkout(product.id);
        });
      }

      grid.appendChild(card);
    });
  } catch (error) {
    setMessage(pageMessage, error.message);
  }
}

async function checkout(productId) {
  try {
    const data = await api(\`/api/market/checkout/\${productId}\`, {
      method: "POST",
      body: "{}"
    });

    if (data.url) {
      window.location.href = data.url;
      return;
    }

    setMessage(pageMessage, data.message || "ชำระเงินสำเร็จ", "success");
    await loadHome();
  } catch (error) {
    setMessage(pageMessage, error.message);
  }
}

/* PRODUCTS */
document.getElementById("productForm").addEventListener("submit", async (event) => {
  event.preventDefault();

  try {
    await api("/api/seller/products", {
      method: "POST",
      body: JSON.stringify({
        name: document.getElementById("productName").value.trim(),
        description: document.getElementById("productDescription").value.trim(),
        imageUrl: document.getElementById("productImage").value.trim(),
        price: document.getElementById("productPrice").value,
        stock: document.getElementById("productStock").value
      })
    });

    event.target.reset();
    document.getElementById("productStock").value = 1;
    setMessage(pageMessage, "เพิ่มสินค้าแล้ว", "success");
    await loadSellerProducts();
  } catch (error) {
    setMessage(pageMessage, error.message);
  }
});

async function loadSellerProducts() {
  try {
    const data = await api("/api/seller/products");
    const box = document.getElementById("sellerProducts");
    box.innerHTML = "";

    if (!data.products.length) {
      box.innerHTML = \`<p class="muted">ยังไม่มีสินค้า</p>\`;
      return;
    }

    data.products.forEach((product) => {
      const item = document.createElement("div");
      item.className = "list-card";

      item.innerHTML = \`
        \${product.image_url
          ? \`<img src="\${escapeHtml(product.image_url)}" alt="">\`
          : \`<div class="list-thumb">◆</div>\`}
        <div class="list-info">
          <strong>\${escapeHtml(product.name)}</strong>
          <small>\${money(product.price_amount, product.currency)} · คงเหลือ \${product.stock} · \${product.active ? "เปิดขาย" : "ปิดขาย"}</small>
        </div>
        <div class="list-actions">
          <button class="mini-btn">ปิดขาย</button>
        </div>
      \`;

      item.querySelector(".mini-btn").addEventListener("click", async () => {
        try {
          await api(\`/api/seller/products/\${product.id}\`, {
            method: "DELETE"
          });
          await loadSellerProducts();
        } catch (error) {
          setMessage(pageMessage, error.message);
        }
      });

      box.appendChild(item);
    });
  } catch (error) {
    setMessage(pageMessage, error.message);
  }
}

/* WALLET */
async function loadWallet() {
  try {
    const [wallet, connect] = await Promise.all([
      api("/api/seller/wallet"),
      api("/api/seller/connect-status")
    ]);

    currency = wallet.currency || currency;

    document.getElementById("walletAvailable").textContent =
      money(wallet.available, wallet.currency);

    document.getElementById("walletPending").textContent =
      money(wallet.pending, wallet.currency);

    const text = document.getElementById("connectText");
    const button = document.getElementById("connectButton");

    if (connect.mode === "demo") {
      text.textContent = "DEMO MODE — ระบบจำลองการรับเงิน/ถอนเงิน";
      button.textContent = "บัญชี DEMO พร้อมใช้งาน";
    } else if (connect.payoutsEnabled) {
      text.textContent = "บัญชีรับเงินเชื่อมต่อและพร้อมถอนเงิน";
      button.textContent = "จัดการบัญชีรับเงิน";
    } else if (connect.connected) {
      text.textContent = "เชื่อมบัญชีแล้ว แต่ยังมีขั้นตอนตรวจสอบ";
      button.textContent = "ดำเนินการต่อ";
    } else {
      text.textContent = "ยังไม่ได้ผูกบัญชีรับเงิน";
      button.textContent = "ผูกบัญชีรับเงิน";
    }
  } catch (error) {
    setMessage(pageMessage, error.message);
  }
}

document.getElementById("connectButton").addEventListener("click", async () => {
  try {
    const data = await api("/api/seller/connect-account", {
      method: "POST",
      body: "{}"
    });

    if (data.url) {
      window.location.href = data.url;
      return;
    }

    setMessage(pageMessage, data.message, "success");
  } catch (error) {
    setMessage(pageMessage, error.message);
  }
});

document.getElementById("withdrawForm").addEventListener("submit", async (event) => {
  event.preventDefault();

  try {
    const data = await api("/api/seller/withdrawals", {
      method: "POST",
      body: JSON.stringify({
        amount: document.getElementById("withdrawAmount").value
      })
    });

    document.getElementById("withdrawAmount").value = "";
    setMessage(pageMessage, data.message, "success");
    await loadWallet();
  } catch (error) {
    setMessage(pageMessage, error.message);
  }
});

/* WITHDRAW HISTORY */
async function loadWithdrawals() {
  try {
    const data = await api("/api/seller/withdrawals");
    const rows = document.getElementById("withdrawalRows");
    rows.innerHTML = "";

    if (!data.withdrawals.length) {
      rows.innerHTML = \`<tr><td colspan="5" class="muted">ยังไม่มีประวัติการถอน</td></tr>\`;
      return;
    }

    data.withdrawals.forEach((w) => {
      const tr = document.createElement("tr");
      tr.innerHTML = \`
        <td>#\${w.id}</td>
        <td>\${money(w.amount, w.currency)}</td>
        <td class="status-\${escapeHtml(w.status)}">\${escapeHtml(w.status)}</td>
        <td>\${escapeHtml(w.provider)}</td>
        <td>\${new Date(w.created_at + "Z").toLocaleString("th-TH")}</td>
      \`;
      rows.appendChild(tr);
    });
  } catch (error) {
    setMessage(pageMessage, error.message);
  }
}

/* PROFILE */
async function loadSellerProfile() {
  try {
    const data = await api("/api/seller/profile");
    const p = data.profile;

    document.getElementById("displayName").value = p.displayName || "";
    document.getElementById("shopName").value = p.shopName || "";
    document.getElementById("shopBio").value = p.bio || "";
    document.getElementById("avatarUrl").value = p.avatarUrl || "";

    updateProfilePreview(p);
  } catch (error) {
    setMessage(pageMessage, error.message);
  }
}

function updateProfilePreview(p) {
  const name = p.displayName || currentUser?.username || "USER";
  document.getElementById("profilePreviewName").textContent = name;
  document.getElementById("profilePreviewShop").textContent =
    p.shopName || "NOIR SHOP";
  document.getElementById("profilePreviewBio").textContent =
    p.bio || "ยังไม่มีรายละเอียดร้าน";

  const image = document.getElementById("profilePreviewImage");
  const fallback = document.getElementById("profilePreviewFallback");
  const navImage = document.getElementById("navAvatar");
  const navFallback = document.getElementById("navAvatarFallback");

  if (p.avatarUrl) {
    image.src = p.avatarUrl;
    image.classList.remove("hidden");
    fallback.classList.add("hidden");

    navImage.src = p.avatarUrl;
    navImage.classList.remove("hidden");
    navFallback.classList.add("hidden");
  } else {
    image.classList.add("hidden");
    fallback.classList.remove("hidden");
    fallback.textContent = name.charAt(0).toUpperCase();

    navImage.classList.add("hidden");
    navFallback.classList.remove("hidden");
  }
}

document.getElementById("sellerProfileForm").addEventListener("submit", async (event) => {
  event.preventDefault();

  try {
    const profile = {
      displayName: document.getElementById("displayName").value.trim(),
      shopName: document.getElementById("shopName").value.trim(),
      bio: document.getElementById("shopBio").value.trim(),
      avatarUrl: document.getElementById("avatarUrl").value.trim()
    };

    await api("/api/seller/profile", {
      method: "PUT",
      body: JSON.stringify(profile)
    });

    updateProfilePreview(profile);
    setMessage(pageMessage, "บันทึกโปรไฟล์แล้ว", "success");
  } catch (error) {
    setMessage(pageMessage, error.message);
  }
});

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/* INITIALIZE */
(async function initialize() {
  const params = new URLSearchParams(window.location.search);
  const verifyToken = params.get("verify");
  resetToken = params.get("reset") || "";

  if (verifyToken) {
    showAuthView("verify");

    try {
      const data = await api("/api/auth/verify-email", {
        method: "POST",
        body: JSON.stringify({ token: verifyToken })
      });

      setMessage(authMessage, data.message, "success");
      history.replaceState({}, "", "/");
    } catch (error) {
      setMessage(authMessage, error.message);
    }

    return;
  }

  if (resetToken) {
    showAuthView("reset");
    history.replaceState({}, "", "/");
    return;
  }

  const loggedIn = await loadMe();

  if (!loggedIn) {
    showAuthView("login");
  }

  if (params.get("checkout") === "success") {
    history.replaceState({}, "", "/");
    setMessage(pageMessage, "ชำระเงินสำเร็จ ระบบกำลังอัปเดตรายการ", "success");
  }

  if (params.get("connect")) {
    history.replaceState({}, "", "/");
    if (loggedIn) {
      showPage("wallet");
    }
  }
})();

</script>
</body>
</html>
`;
app.get("/", (req,res)=>res.type("html").send(PAGE));
app.get("*",(req,res)=>res.redirect("/"));

app.listen(config.port,()=>{
  console.log(`NOIR BLOOD running: ${config.appUrl}`);
  console.log(`PAYMENT_MODE=${config.paymentMode}`);
  console.log(`MAIL_MODE=${config.mailMode}`);
});
