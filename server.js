// CerebralSupport — Node + PostgreSQL (Railway). Accounts, registration, admin panel. Only dependency: pg
const http=require("http"),fs=require("fs"),path=require("path"),crypto=require("crypto");
const {Pool}=require("pg");
const PORT=process.env.PORT||3000,DB=process.env.DATABASE_URL,PW=process.env.APP_PASSWORD,SEC=process.env.SESSION_SECRET;
if(!DB||!PW||!SEC){console.error("Missing env vars. Required: DATABASE_URL, APP_PASSWORD, SESSION_SECRET");process.exit(1)}
const pool=new Pool({connectionString:DB,ssl:DB.includes("railway.internal")||process.env.PGSSL==="disable"?false:{rejectUnauthorized:false}});
const INIT=`CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY,fname TEXT NOT NULL,lname TEXT NOT NULL,name_key TEXT NOT NULL,phone TEXT NOT NULL UNIQUE,pass TEXT NOT NULL,created_at TIMESTAMPTZ DEFAULT now(),last_login TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS patients(id SERIAL PRIMARY KEY,name TEXT NOT NULL,age INT DEFAULT 0,gender TEXT DEFAULT '',notes TEXT DEFAULT '',created_at TIMESTAMPTZ DEFAULT now());
ALTER TABLE patients ADD COLUMN IF NOT EXISTS user_id INT REFERENCES users(id) ON DELETE CASCADE;
CREATE TABLE IF NOT EXISTS sessions(id SERIAL PRIMARY KEY,patient_id INT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,game TEXT,t BIGINT,score INT DEFAULT 0,level INT DEFAULT 1,dur INT DEFAULT 0,ok INT DEFAULT 0,bad INT DEFAULT 0,pm INT DEFAULT 0,pa INT DEFAULT 0);
CREATE INDEX IF NOT EXISTS sessions_patient_idx ON sessions(patient_id);
CREATE INDEX IF NOT EXISTS patients_user_idx ON patients(user_id);`;
/* ---- helpers ---- */
const sign=p=>crypto.createHmac("sha256",SEC).update(p).digest("base64url");
const mkTok=(u,r)=>{const p=Buffer.from(JSON.stringify({u,r,exp:Date.now()+30*864e5})).toString("base64url");return p+"."+sign(p)};
const readTok=t=>{try{const [p,s]=String(t).split(".");const a=Buffer.from(sign(p)),b=Buffer.from(s||"");if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return null;const o=JSON.parse(Buffer.from(p,"base64url"));return o.exp>Date.now()?o:null}catch(e){return null}};
const hash=s=>crypto.createHash("sha256").update(String(s)).digest();
const sameStr=(a,b)=>crypto.timingSafeEqual(hash(a),hash(b));
const hp=pw=>new Promise((ok,no)=>{const s=crypto.randomBytes(16).toString("hex");crypto.scrypt(String(pw),s,64,(e,k)=>e?no(e):ok(s+":"+k.toString("hex")))});
const vp=(pw,st)=>new Promise(ok=>{const [s,h]=String(st||"").split(":");if(!s||!h)return ok(false);crypto.scrypt(String(pw),s,64,(e,k)=>{try{ok(!e&&k.length===Buffer.from(h,"hex").length&&crypto.timingSafeEqual(k,Buffer.from(h,"hex")))}catch(x){ok(false)}})});
const att=new Map();
const limited=(k,ip,max,win)=>{const key=k+":"+ip,n=Date.now(),a=(att.get(key)||[]).filter(t=>n-t<win);att.set(key,a);return a.length>=max};
const hit=(k,ip)=>{const key=k+":"+ip,a=att.get(key)||[];a.push(Date.now());att.set(key,a)};
const nm=s=>String(s||"").normalize("NFKC").replace(/[يى]/g,"ی").replace(/ك/g,"ک").replace(/[ۀة]/g,"ه").replace(/[أإآ]/g,"ا").replace(/[\u064B-\u065F\u0670\u200c\u200d\u200e\u200f\s\-_.'"]/g,"").toLowerCase();
const lev=(a,b)=>{if(Math.abs(a.length-b.length)>1)return 2;const d=[];for(let i=0;i<=a.length;i++){d[i]=[i]}for(let j=1;j<=b.length;j++)d[0][j]=j;for(let i=1;i<=a.length;i++)for(let j=1;j<=b.length;j++)d[i][j]=Math.min(d[i-1][j]+1,d[i][j-1]+1,d[i-1][j-1]+(a[i-1]===b[j-1]?0:1));return d[a.length][b.length]};
const dg=s=>String(s||"").replace(/[۰-۹]/g,c=>c.charCodeAt(0)-1776).replace(/[٠-٩]/g,c=>c.charCodeAt(0)-1632).replace(/\D/g,"");
const phone=s=>{let d=dg(s);if(d.startsWith("0098"))d="0"+d.slice(4);else if(d.startsWith("98")&&d.length===12)d="0"+d.slice(2);else if(d.length===10&&d[0]==="9")d="0"+d;return d};
const send=(res,code,obj)=>{res.writeHead(code,{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store","X-Content-Type-Options":"nosniff"});res.end(obj==null?"":JSON.stringify(obj))};
const body=req=>new Promise((ok,no)=>{let n=0;const c=[];req.on("data",d=>{n+=d.length;if(n>5e6){no(new Error("big"));req.destroy()}else c.push(d)});req.on("end",()=>{try{ok(c.length?JSON.parse(Buffer.concat(c).toString()):{})}catch(e){no(new Error("json"))}});req.on("error",no)});
const N=v=>Number.isFinite(+v)?Math.max(0,Math.round(+v)):0,T=(v,m)=>String(v==null?"":v).slice(0,m||500);
const pat=b=>[T(b.name,200).trim(),N(b.age),T(b.gender,20),T(b.notes,2000)];
const ses=(pid,x,uid)=>[pid,T(x.g||x.game,40),N(x.t)||Date.now(),N(x.score),Math.max(1,N(x.level)),N(x.dur),N(x.ok),N(x.bad),N(x.pm),N(x.pa),uid];
const SINS="INSERT INTO sessions(patient_id,game,t,score,level,dur,ok,bad,pm,pa) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10 WHERE EXISTS(SELECT 1 FROM patients WHERE id=$1 AND user_id=$11) RETURNING id";
const SCOLS="s.id,s.patient_id AS pid,s.game AS g,s.t,s.score,s.level,s.dur,s.ok,s.bad,s.pm,s.pa";
const fixT=r=>Object.assign({},r,{t:Number(r.t)});
async function isDup(ph){return (await pool.query("SELECT id FROM users WHERE phone=$1",[ph])).rows.length>0}
/* ---- server ---- */
const server=http.createServer(async(req,res)=>{
 try{
  const u=new URL(req.url,"http://x").pathname,m=req.method,ip=String(req.headers["x-forwarded-for"]||req.socket.remoteAddress||"").split(",")[0].trim();
  if(m==="GET"&&(u==="/"||u==="/index.html"||u==="/admin"||u==="/admin/")){return fs.readFile(path.join(__dirname,"index.html"),(e,b)=>{if(e){res.writeHead(404);return res.end("index.html not found")}res.writeHead(200,{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-cache","Permissions-Policy":"camera=(self)",...(u.startsWith("/admin")?{"X-Robots-Tag":"noindex, nofollow"}:{}),"X-Content-Type-Options":"nosniff"});res.end(b)})}
  if(!u.startsWith("/api/")){res.writeHead(404);return res.end("Not found")}
  if(u==="/api/health"&&m==="GET")return send(res,200,{ok:true});
  if(u==="/api/register"&&m==="POST"){
   if(limited("reg",ip,20,36e5))return send(res,429,{error:"too_many"});hit("reg",ip);
   const b=await body(req),f=T(b.first,40).trim(),l=T(b.last,40).trim(),ph=phone(b.phone),pw=String(b.password||"");
   if(f.length<2||l.length<2)return send(res,400,{error:"invalid_name"});
   if(!/^\d{8,15}$/.test(ph)||(ph.startsWith("0")&&ph.length!==11))return send(res,400,{error:"invalid_phone"});
   if(pw.length<6||pw.length>100)return send(res,400,{error:"weak_password"});
   if(await isDup(ph))return send(res,409,{error:"duplicate"});
   try{const r=await pool.query("INSERT INTO users(fname,lname,name_key,phone,pass) VALUES($1,$2,$3,$4,$5) RETURNING id",[f,l,nm(f)+nm(l),ph,await hp(pw)]);
    return send(res,200,{token:mkTok(r.rows[0].id,"user"),role:"user",name:f+" "+l})}
   catch(e){if(e.code==="23505")return send(res,409,{error:"duplicate"});throw e}}
  if(u==="/api/admin/login"&&m==="POST"){
   if(limited("log",ip,10,6e4))return send(res,429,{error:"too_many"});
   const b=await body(req);if(sameStr(b.password,PW))return send(res,200,{token:mkTok(0,"admin"),role:"admin",name:"admin"});hit("log",ip);return send(res,401,{error:"bad_login"})}
  if(u==="/api/login"&&m==="POST"){
   if(limited("log",ip,10,6e4))return send(res,429,{error:"too_many"});
   const b=await body(req),id=String(b.username||b.phone||"").trim();
   const r=await pool.query("SELECT id,fname,lname,pass FROM users WHERE phone=$1",[phone(id)]),x=r.rows[0];
   if(!x||!(await vp(b.password,x.pass))){hit("log",ip);return send(res,401,{error:"bad_login"})}
   await pool.query("UPDATE users SET last_login=now() WHERE id=$1",[x.id]);
   return send(res,200,{token:mkTok(x.id,"user"),role:"user",name:x.fname+" "+x.lname})}
  const tk=readTok(String(req.headers.authorization||"").replace(/^Bearer /,""));
  if(!tk)return send(res,401,{error:"auth"});
  /* ---- admin ---- */
  if(u.startsWith("/api/admin/")){
   if(tk.r!=="admin")return send(res,403,{error:"forbidden"});
   if(u==="/api/admin/all"&&m==="GET"){const [a,b,c]=await Promise.all([pool.query("SELECT id,fname,lname,phone,created_at,last_login FROM users ORDER BY id"),pool.query("SELECT id,user_id AS uid,name,age,gender,notes FROM patients WHERE user_id IS NOT NULL ORDER BY id"),pool.query("SELECT "+SCOLS+" FROM sessions s JOIN patients p ON p.id=s.patient_id WHERE p.user_id IS NOT NULL ORDER BY s.t")]);
    return send(res,200,{users:a.rows,patients:b.rows,sessions:c.rows.map(fixT)})}
   let k=u.match(/^\/api\/admin\/users\/(\d+)$/);
   if(k&&m==="DELETE"){await pool.query("DELETE FROM users WHERE id=$1",[k[1]]);return send(res,200,{ok:true})}
   k=u.match(/^\/api\/admin\/users\/(\d+)\/password$/);
   if(k&&m==="POST"){const pw=String((await body(req)).password||"");if(pw.length<6)return send(res,400,{error:"weak_password"});await pool.query("UPDATE users SET pass=$2 WHERE id=$1",[k[1],await hp(pw)]);return send(res,200,{ok:true})}
   return send(res,404,{error:"not_found"})}
  /* ---- user data ---- */
  if(tk.r==="admin"){if(u==="/api/state"&&m==="GET")return send(res,200,{role:"admin",name:"admin",patients:[],sessions:[]});return send(res,403,{error:"forbidden"})}
  const uid=tk.u;let r;
  if(u==="/api/state"&&m==="GET"){const me=(await pool.query("SELECT fname,lname FROM users WHERE id=$1",[uid])).rows[0];if(!me)return send(res,401,{error:"auth"});
   const [p,s]=await Promise.all([pool.query("SELECT id,name,age,gender,notes FROM patients WHERE user_id=$1 ORDER BY id",[uid]),pool.query("SELECT "+SCOLS+" FROM sessions s JOIN patients p ON p.id=s.patient_id WHERE p.user_id=$1 ORDER BY s.t",[uid])]);
   return send(res,200,{role:"user",name:me.fname+" "+me.lname,patients:p.rows,sessions:s.rows.map(fixT)})}
  if(u==="/api/patients"&&m==="POST"){const a=pat(await body(req));if(!a[0])return send(res,400,{error:"name"});r=await pool.query("INSERT INTO patients(name,age,gender,notes,user_id) VALUES($1,$2,$3,$4,$5) RETURNING id",[...a,uid]);return send(res,200,{id:r.rows[0].id})}
  let k=u.match(/^\/api\/patients\/(\d+)$/);
  if(k&&m==="PUT"){const a=pat(await body(req));if(!a[0])return send(res,400,{error:"name"});await pool.query("UPDATE patients SET name=$3,age=$4,gender=$5,notes=$6 WHERE id=$1 AND user_id=$2",[k[1],uid,...a]);return send(res,200,{ok:true})}
  if(k&&m==="DELETE"){await pool.query("DELETE FROM patients WHERE id=$1 AND user_id=$2",[k[1],uid]);return send(res,200,{ok:true})}
  if(u==="/api/sessions"&&m==="POST"){const b=await body(req);r=await pool.query(SINS,ses(N(b.pid),b,uid));if(!r.rows.length)return send(res,400,{error:"patient"});return send(res,200,{id:r.rows[0].id})}
  k=u.match(/^\/api\/sessions\/(\d+)$/);
  if(k&&m==="DELETE"){await pool.query("DELETE FROM sessions s USING patients p WHERE s.id=$1 AND s.patient_id=p.id AND p.user_id=$2",[k[1],uid]);return send(res,200,{ok:true})}
  if(u==="/api/import"&&m==="POST"){const b=await body(req);const P=Array.isArray(b.patients)?b.patients.slice(0,5000):[],S=Array.isArray(b.sessions)?b.sessions.slice(0,200000):[];
   const cl=await pool.connect();try{await cl.query("BEGIN");const map={};for(const p of P){const a=pat(p);if(!a[0])continue;map[p.id]=(await cl.query("INSERT INTO patients(name,age,gender,notes,user_id) VALUES($1,$2,$3,$4,$5) RETURNING id",[...a,uid])).rows[0].id}
   for(const x of S){if(map[x.pid])await cl.query(SINS,ses(map[x.pid],x,uid))}await cl.query("COMMIT")}catch(e){await cl.query("ROLLBACK");throw e}finally{cl.release()}
   return send(res,200,{ok:true})}
  send(res,404,{error:"not_found"})
 }catch(e){console.error(e);if(!res.headersSent)send(res,e.message==="json"||e.message==="big"?400:500,{error:"server"})}
});
(async()=>{try{await pool.query(INIT);console.log("DB ready")}catch(e){console.error("DB init failed:",e.message)}
 server.listen(PORT,"0.0.0.0",()=>console.log("Listening on "+PORT))})();
process.on("SIGTERM",()=>{server.close(()=>pool.end().then(()=>process.exit(0)))});
