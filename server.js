require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("Set a strong JWT_SECRET (at least 32 characters) in .env");
  process.exit(1);
}
const db = new Database(process.env.DB_FILE || "krishok-bazar.sqlite");
const DISTRICTS = ["ঢাকা", "গাজীপুর", "নারায়ণগঞ্জ", "নরসিংদী", "মুন্সিগঞ্জ", "মানিকগঞ্জ", "মাদারীপুর", "শরীয়তপুর", "ফরিদপুর", "রাজবাড়ী", "গোপালগঞ্জ", "টাঙ্গাইল", "কিশোরগঞ্জ", "চট্টগ্রাম", "কক্সবাজার", "কুমিল্লা", "ব্রাহ্মণবাড়িয়া", "চাঁদপুর", "ফেনী", "নোয়াখালী", "লক্ষ্মীপুর", "রাঙ্গামাটি", "খাগড়াছড়ি", "বান্দরবান", "রাজশাহী", "নাটোর", "নওগাঁ", "চাঁপাইনবাবগঞ্জ", "পাবনা", "সিরাজগঞ্জ", "বগুড়া", "জয়পুরহাট", "খুলনা", "যশোর", "সাতক্ষীরা", "বাগেরহাট", "নড়াইল", "মাগুরা", "ঝিনাইদহ", "কুষ্টিয়া", "চুয়াডাঙ্গা", "মেহেরপুর", "বরিশাল", "পটুয়াখালী", "ভোলা", "পিরোজপুর", "বরগুনা", "ঝালকাঠি", "সিলেট", "মৌলভীবাজার", "হবিগঞ্জ", "সুনামগঞ্জ", "রংপুর", "দিনাজপুর", "গাইবান্ধা", "কুড়িগ্রাম", "লালমনিরহাট", "নীলফামারী", "ঠাকুরগাঁও", "পঞ্চগড়", "ময়মনসিংহ", "জামালপুর", "শেরপুর", "নেত্রকোণা"];
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 phone TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('farmer','buyer','admin')),
 district TEXT NOT NULL,
 verified INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS products (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 seller_id INTEGER NOT NULL REFERENCES users(id),
 name TEXT NOT NULL,
 category TEXT NOT NULL,
 description TEXT DEFAULT '',
 price_bdt REAL NOT NULL CHECK(price_bdt > 0),
 unit TEXT NOT NULL,
 quantity REAL NOT NULL CHECK(quantity > 0),
 district TEXT NOT NULL,
 contact_phone TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','sold_out','hidden')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS orders (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 buyer_id INTEGER NOT NULL REFERENCES users(id),
 product_id INTEGER NOT NULL REFERENCES products(id),
 seller_id INTEGER NOT NULL REFERENCES users(id),
 quantity REAL NOT NULL CHECK(quantity > 0),
 unit_price_bdt REAL NOT NULL,
 total_bdt REAL NOT NULL,
 delivery_address TEXT NOT NULL,
 buyer_phone TEXT NOT NULL,
 payment_method TEXT NOT NULL CHECK(payment_method IN ('cash_on_delivery','direct_contact')),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','rejected','processing','shipped','completed','cancelled')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_products_category ON products(category);
CREATE INDEX IF NOT EXISTS idx_products_district ON products(district);
CREATE INDEX IF NOT EXISTS idx_orders_buyer ON orders(buyer_id);
CREATE INDEX IF NOT EXISTS idx_orders_seller ON orders(seller_id);
CREATE TABLE IF NOT EXISTS market_prices (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 farmer_id INTEGER NOT NULL REFERENCES users(id),
 product_name TEXT NOT NULL,
 market_name TEXT NOT NULL,
 district TEXT NOT NULL,
 price_bdt REAL NOT NULL CHECK(price_bdt > 0),
 unit TEXT NOT NULL,
 source_note TEXT DEFAULT '',
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 reviewed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_market_prices_district ON market_prices(district);
CREATE INDEX IF NOT EXISTS idx_market_prices_status ON market_prices(status);
CREATE TABLE IF NOT EXISTS product_reports (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 product_id INTEGER NOT NULL REFERENCES products(id),
 reporter_id INTEGER REFERENCES users(id),
 reason TEXT NOT NULL,
 details TEXT DEFAULT '',
 status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','reviewed','dismissed')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

app.use(helmet({contentSecurityPolicy:false}));
app.use(cors({origin: process.env.CORS_ORIGIN || true}));
app.use(express.json({limit:"200kb"}));
app.use(rateLimit({windowMs:15*60*1000,limit:250,standardHeaders:true,legacyHeaders:false}));
app.use(express.static(path.join(__dirname,"public")));

function clean(v,max=160){return String(v??"").trim().slice(0,max)}
function auth(req,res,next){
 const h=req.headers.authorization||"";
 try { req.user=jwt.verify(h.startsWith("Bearer ")?h.slice(7):"",JWT_SECRET); next(); }
 catch { return res.status(401).json({error:"লগইন প্রয়োজন"}); }
}
function role(...roles){return (req,res,next)=>roles.includes(req.user.role)?next():res.status(403).json({error:"এই কাজের অনুমতি নেই"});}
function token(user){return jwt.sign({id:user.id,role:user.role,name:user.name},JWT_SECRET,{expiresIn:"7d"});}
function publicUser(u){return {id:u.id,name:u.name,phone:u.phone,role:u.role,district:u.district,verified:!!u.verified};}

app.get("/api/districts",(req,res)=>res.json({districts:DISTRICTS}));
app.get("/api/health",(req,res)=>res.json({ok:true,service:"Krishok Bazar"}));

// Farmer-submitted market prices are community reports, not official DAM rates.
app.get("/api/market-prices",(req,res)=>{
 const district=clean(req.query.district,80), q=clean(req.query.q,100);
 const rows=db.prepare(`SELECT mp.id,mp.product_name,mp.market_name,mp.district,mp.price_bdt,mp.unit,mp.source_note,mp.created_at,u.name farmer_name
 FROM market_prices mp JOIN users u ON u.id=mp.farmer_id
 WHERE mp.status='approved' AND (?='' OR mp.district=?) AND (?='' OR mp.product_name LIKE '%'||?||'%')
 ORDER BY mp.created_at DESC LIMIT 250`).all(district,district,q,q);
 res.json({prices:rows,notice:"এগুলো কৃষকের জমা দেওয়া ও যাচাইকৃত স্থানীয় বাজারদর; সরকারি DAM দর নয়।"});
});
app.post("/api/market-prices",auth,role("farmer"),(req,res)=>{
 const b=req.body, product=clean(b.product_name,100), market=clean(b.market_name,120);
 const district=clean(b.district,80), unit=clean(b.unit,20), note=clean(b.source_note,300), price=Number(b.price_bdt);
 if(!product||!market||!DISTRICTS.includes(district)||!unit||!Number.isFinite(price)||price<=0)
  return res.status(400).json({error:"পণ্য, বাজার, সঠিক জেলা, দাম ও একক দিন"});
 const info=db.prepare("INSERT INTO market_prices(farmer_id,product_name,market_name,district,price_bdt,unit,source_note) VALUES(?,?,?,?,?,?,?)")
 .run(req.user.id,product,market,district,price,unit,note);
 res.status(201).json({id:info.lastInsertRowid,status:"pending",message:"বাজারদর জমা হয়েছে; অনুমোদনের পর সবার কাছে দেখা যাবে"});
});
app.post("/api/products/:id/report",(req,res)=>{
 const id=Number(req.params.id), reason=clean(req.body.reason,80), details=clean(req.body.details,500);
 const product=db.prepare("SELECT id FROM products WHERE id=?").get(id);
 if(!product)return res.status(404).json({error:"পণ্য পাওয়া যায়নি"});
 if(!["ভুল দাম","ভুয়া পণ্য","ভুল যোগাযোগ","অন্যান্য"].includes(reason))return res.status(400).json({error:"রিপোর্টের কারণ নির্বাচন করুন"});
 const reporterId=req.headers.authorization ? (()=>{try{return jwt.verify(req.headers.authorization.replace(/^Bearer /,""),JWT_SECRET).id}catch{return null}})() : null;
 db.prepare("INSERT INTO product_reports(product_id,reporter_id,reason,details) VALUES(?,?,?,?)").run(id,reporterId,reason,details);
 res.status(201).json({message:"রিপোর্ট গ্রহণ করা হয়েছে"});
});

app.post("/api/auth/register", async (req,res)=>{
 try{
  const name=clean(req.body.name,100), phone=clean(req.body.phone,20), password=String(req.body.password||"");
  const roleValue=req.body.role, district=clean(req.body.district,80);
  if(!name||!/^01[3-9]\d{8}$/.test(phone)||password.length<8||!["farmer","buyer"].includes(roleValue)||!DISTRICTS.includes(district))
    return res.status(400).json({error:"সঠিক নাম, বাংলাদেশি মোবাইল নম্বর, জেলা, ভূমিকা এবং কমপক্ষে ৮ অক্ষরের পাসওয়ার্ড দিন"});
  const hash=await bcrypt.hash(password,12);
  const info=db.prepare("INSERT INTO users(name,phone,password_hash,role,district) VALUES(?,?,?,?,?)").run(name,phone,hash,roleValue,district);
  const u=db.prepare("SELECT * FROM users WHERE id=?").get(info.lastInsertRowid);
  res.status(201).json({token:token(u),user:publicUser(u)});
 }catch(e){res.status(409).json({error:e.code==="SQLITE_CONSTRAINT_UNIQUE"?"এই মোবাইল নম্বরে অ্যাকাউন্ট আছে":"নিবন্ধন করা যায়নি"});}
});

app.post("/api/auth/login",async(req,res)=>{
 const phone=clean(req.body.phone,20), password=String(req.body.password||"");
 const u=db.prepare("SELECT * FROM users WHERE phone=?").get(phone);
 if(!u||!(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({error:"মোবাইল নম্বর বা পাসওয়ার্ড সঠিক নয়"});
 res.json({token:token(u),user:publicUser(u)});
});
app.get("/api/me",auth,(req,res)=>{
 const u=db.prepare("SELECT * FROM users WHERE id=?").get(req.user.id);
 if(!u)return res.status(404).json({error:"অ্যাকাউন্ট পাওয়া যায়নি"});
 res.json({user:publicUser(u)});
});

app.get("/api/products",(req,res)=>{
 const q=clean(req.query.q,100), category=clean(req.query.category,60), district=clean(req.query.district,80);
 const rows=db.prepare(`SELECT p.id,p.name,p.category,p.description,p.price_bdt,p.unit,p.quantity,p.district,p.contact_phone,p.created_at,u.name seller_name,u.verified seller_verified
 FROM products p JOIN users u ON u.id=p.seller_id WHERE p.status='active'
 AND (?='' OR p.name LIKE '%'||?||'%' OR p.description LIKE '%'||?||'%')
 AND (?='' OR p.category=?) AND (?='' OR p.district=?)
 ORDER BY p.created_at DESC LIMIT 200`).all(q,q,q,category,category,district,district);
 res.json({products:rows});
});
app.post("/api/products",auth,role("farmer"),(req,res)=>{
 const b=req.body, name=clean(b.name,120), category=clean(b.category,60), description=clean(b.description,1000);
 const unit=clean(b.unit,20), district=clean(b.district,80), contact=clean(b.contact_phone,20);
 const price=Number(b.price_bdt), quantity=Number(b.quantity);
 const cats=["ধান ও শস্য","ডাল ও মসলা","সবজি","ফল","মাছ","অন্যান্য"];
 if(!name||!cats.includes(category)||!unit||!DISTRICTS.includes(district)||!/^01[3-9]\d{8}$/.test(contact)||!Number.isFinite(price)||price<=0||!Number.isFinite(quantity)||quantity<=0)
  return res.status(400).json({error:"পণ্যের সব তথ্য সঠিকভাবে দিন"});
 const info=db.prepare("INSERT INTO products(seller_id,name,category,description,price_bdt,unit,quantity,district,contact_phone) VALUES(?,?,?,?,?,?,?,?,?)")
 .run(req.user.id,name,category,description,price,unit,quantity,district,contact);
 res.status(201).json({id:info.lastInsertRowid,message:"পণ্য প্রকাশিত হয়েছে"});
});
app.patch("/api/products/:id",auth,role("farmer","admin"),(req,res)=>{
 const p=db.prepare("SELECT * FROM products WHERE id=?").get(Number(req.params.id));
 if(!p)return res.status(404).json({error:"পণ্য পাওয়া যায়নি"});
 if(req.user.role!=="admin"&&p.seller_id!==req.user.id)return res.status(403).json({error:"নিজের পণ্যই সম্পাদনা করতে পারবেন"});
 const status=clean(req.body.status,20);
 if(!["active","sold_out","hidden"].includes(status))return res.status(400).json({error:"অবস্থা সঠিক নয়"});
 db.prepare("UPDATE products SET status=? WHERE id=?").run(status,p.id);
 res.json({message:"পণ্যের অবস্থা আপডেট হয়েছে"});
});

app.post("/api/orders",auth,role("buyer"),(req,res)=>{
 const productId=Number(req.body.product_id), quantity=Number(req.body.quantity);
 const address=clean(req.body.delivery_address,500), phone=clean(req.body.buyer_phone,20);
 const method=req.body.payment_method;
 const p=db.prepare("SELECT * FROM products WHERE id=? AND status='active'").get(productId);
 if(!p)return res.status(404).json({error:"পণ্যটি পাওয়া যায়নি"});
 if(p.seller_id===req.user.id)return res.status(400).json({error:"নিজের পণ্য অর্ডার করা যাবে না"});
 if(!Number.isFinite(quantity)||quantity<=0||quantity>p.quantity||!address||!/^01[3-9]\d{8}$/.test(phone)||!["cash_on_delivery","direct_contact"].includes(method))
  return res.status(400).json({error:"অর্ডারের তথ্য সঠিক নয় বা পর্যাপ্ত পণ্য নেই"});
 const total=quantity*p.price_bdt;
 const info=db.prepare("INSERT INTO orders(buyer_id,product_id,seller_id,quantity,unit_price_bdt,total_bdt,delivery_address,buyer_phone,payment_method) VALUES(?,?,?,?,?,?,?,?,?)")
 .run(req.user.id,p.id,p.seller_id,quantity,p.price_bdt,total,address,phone,method);
 res.status(201).json({order_id:info.lastInsertRowid,total_bdt:total,status:"pending",message:"অর্ডার অনুরোধ পাঠানো হয়েছে"});
});
app.get("/api/orders",auth,(req,res)=>{
 const rows=req.user.role==="admin"
 ? db.prepare("SELECT o.*,p.name product_name,b.name buyer_name,s.name seller_name FROM orders o JOIN products p ON p.id=o.product_id JOIN users b ON b.id=o.buyer_id JOIN users s ON s.id=o.seller_id ORDER BY o.created_at DESC LIMIT 300").all()
 : db.prepare("SELECT o.*,p.name product_name,b.name buyer_name,s.name seller_name FROM orders o JOIN products p ON p.id=o.product_id JOIN users b ON b.id=o.buyer_id JOIN users s ON s.id=o.seller_id WHERE o.buyer_id=? OR o.seller_id=? ORDER BY o.created_at DESC").all(req.user.id,req.user.id);
 res.json({orders:rows});
});
app.patch("/api/orders/:id/status",auth,role("farmer","admin"),(req,res)=>{
 const o=db.prepare("SELECT * FROM orders WHERE id=?").get(Number(req.params.id));
 if(!o)return res.status(404).json({error:"অর্ডার পাওয়া যায়নি"});
 if(req.user.role!=="admin"&&o.seller_id!==req.user.id)return res.status(403).json({error:"এই অর্ডার আপনার নয়"});
 const allowed=["accepted","rejected","processing","shipped","completed","cancelled"];
 if(!allowed.includes(req.body.status))return res.status(400).json({error:"অবস্থা সঠিক নয়"});
 db.prepare("UPDATE orders SET status=? WHERE id=?").run(req.body.status,o.id);
 res.json({message:"অর্ডারের অবস্থা পরিবর্তন হয়েছে"});
});

app.get("/api/admin/market-prices",auth,role("admin"),(req,res)=>{
 const status=clean(req.query.status,20);
 const rows=db.prepare(`SELECT mp.*,u.name farmer_name,u.phone farmer_phone FROM market_prices mp JOIN users u ON u.id=mp.farmer_id
 WHERE (?='' OR mp.status=?) ORDER BY mp.created_at DESC LIMIT 300`).all(status,status);
 res.json({prices:rows});
});
app.patch("/api/admin/market-prices/:id",auth,role("admin"),(req,res)=>{
 const status=clean(req.body.status,20);
 if(!["approved","rejected"].includes(status))return res.status(400).json({error:"অনুমোদন বা বাতিল নির্বাচন করুন"});
 const info=db.prepare("UPDATE market_prices SET status=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=?").run(status,Number(req.params.id));
 if(!info.changes)return res.status(404).json({error:"বাজারদরের তথ্য পাওয়া যায়নি"});
 res.json({message:status==="approved"?"বাজারদর অনুমোদিত":"বাজারদর বাতিল"});
});
app.get("/api/admin/product-reports",auth,role("admin"),(req,res)=>{
 const rows=db.prepare(`SELECT r.*,p.name product_name,u.name reporter_name FROM product_reports r
 JOIN products p ON p.id=r.product_id LEFT JOIN users u ON u.id=r.reporter_id
 ORDER BY r.created_at DESC LIMIT 300`).all();
 res.json({reports:rows});
});
app.patch("/api/admin/product-reports/:id",auth,role("admin"),(req,res)=>{
 const status=clean(req.body.status,20);
 if(!["reviewed","dismissed"].includes(status))return res.status(400).json({error:"সঠিক অবস্থা দিন"});
 const info=db.prepare("UPDATE product_reports SET status=? WHERE id=?").run(status,Number(req.params.id));
 if(!info.changes)return res.status(404).json({error:"রিপোর্ট পাওয়া যায়নি"});
 res.json({message:"রিপোর্ট আপডেট হয়েছে"});
});

app.get("/api/admin/summary",auth,role("admin"),(req,res)=>{
 res.json({
  users:db.prepare("SELECT role,COUNT(*) count FROM users GROUP BY role").all(),
  products:db.prepare("SELECT COUNT(*) count FROM products").get().count,
  orders:db.prepare("SELECT status,COUNT(*) count FROM orders GROUP BY status").all()
 });
});
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`Krishok Bazar running on port ${PORT}`));
