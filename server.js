// CerebralSupport — Node + PostgreSQL server for Railway (only dependency: pg)
const http=require("http"),fs=require("fs"),path=require("path"),crypto=require("crypto");
const {Pool}=require("pg");
const PORT=process.env.PORT||3000,DB=process.env.DATABASE_URL,PW=process.env.APP_PASSWORD,SEC=process.env.SESSION_SECRET;
if(!DB||!PW||!SEC){console.error("Missing env vars. Required: DATABASE_URL, APP_PASSWORD, SESSION_SECRET");process.exit(1)}
const pool=new Pool({connectionString:DB,ssl:DB.includes("railway.internal")||process.env.PGSSL==="disable"?false:{rejectUnauthorized:false}});
const INIT=`CREATE TABLE IF NOT EXISTS patients(id SERIAL PRIMARY KEY,name TEXT NOT NULL,age INT DEFAULT 0,gender TEXT DEFAULT '',notes TEXT DEFAULT '',created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS sessions(id SERIAL PRIMARY KEY,patient_id INT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,game TEXT,t BIGINT,score INT DEFAULT 0,level INT DEFAULT 1,dur INT DEFAULT 0,ok INT DEFAULT 0,bad INT DEFAULT 0,pm INT DEFAULT 0,pa INT DEFAULT 0);
CREATE INDEX IF NOT EXISTS sessions_patient_idx ON sessions(patient_id);`;
const sign=p=>crypto.createHmac("sha256",SEC).update(p).digest("base64url");
const mkTok=()=>{const p=Buffer.from(JSON.stringify({exp:Date.now()+30*864e5})).toString("base64url");return p+"."+sign(p)};
const okTok=t=>{try{const [p,s]=String(t).split(".");const a=Buffer.from(sign(p)),b=Buffer.from(s||"");return a.length===b.length&&crypto.timingSafeEqual(a,b)&&JSON.parse(Buffer.from(p,"base64url")).exp>Date.now()}catch(e){return false}};
const hash=s=>crypto.createHash("sha256").update(String(s)).digest();
const pwOk=s=>crypto.timingSafeEqual(hash(s),hash(PW));
const att=new Map();
const limited=ip=>{const n=Date.now(),a=(att.get(ip)||[]).filter(t=>n-t<6e4);att.set(ip,a);return a.length>=8};
const fail=ip=>{const a=att.get(ip)||[];a.push(Date.now());att.set(ip,a)};
const send=(res,code,obj)=>{res.writeHead(code,{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store","X-Content-Type-Options":"nosniff"});res.end(obj==null?"":JSON.stringify(obj))};
const body=req=>new Promise((ok,no)=>{let n=0;const c=[];req.on("data",d=>{n+=d.length;if(n>5e6){no(new Error("big"));req.destroy()}else c.push(d)});req.on("end",()=>{try{ok(c.length?JSON.parse(Buffer.concat(c).toString()):{})}catch(e){no(new Error("json"))}});req.on("error",no)});
const N=v=>Number.isFinite(+v)?Math.max(0,Math.round(+v)):0,T=(v,m)=>String(v==null?"":v).slice(0,m||500);
const pat=b=>[T(b.name,200).trim(),N(b.age),T(b.gender,20),T(b.notes,2000)];
const ses=(pid,x)=>[pid,T(x.g||x.game,40),N(x.t)||Date.now(),N(x.score),Math.max(1,N(x.level)),N(x.dur),N(x.ok),N(x.bad),N(x.pm),N(x.pa)];
const SINS="INSERT INTO sessions(patient_id,game,t,score,level,dur,ok,bad,pm,pa) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id";
const server=http.createServer(async(req,res)=>{
 try{
  const u=new URL(req.url,"http://x").pathname,m=req.method,ip=String(req.headers["x-forwarded-for"]||req.socket.remoteAddress||"").split(",")[0].trim();
  if(m==="GET"&&(u==="/"||u==="/index.html")){return fs.readFile(path.join(__dirname,"index.html"),(e,b)=>{if(e){res.writeHead(404);return res.end("index.html not found")}res.writeHead(200,{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-cache","Permissions-Policy":"camera=(self)","X-Content-Type-Options":"nosniff"});res.end(b)})}
  if(!u.startsWith("/api/")){res.writeHead(404);return res.end("Not found")}
  if(u==="/api/health"&&m==="GET")return send(res,200,{ok:true});
  if(u==="/api/login"&&m==="POST"){if(limited(ip))return send(res,429,{error:"too_many"});const b=await body(req);if(!pwOk(b.password)){fail(ip);return send(res,401,{error:"bad_password"})}return send(res,200,{token:mkTok()})}
  const h=String(req.headers.authorization||"");if(!okTok(h.replace(/^Bearer /,"")))return send(res,401,{error:"auth"});
  let r;
  if(u==="/api/state"&&m==="GET"){const [p,s]=await Promise.all([pool.query("SELECT id,name,age,gender,notes FROM patients ORDER BY id"),pool.query("SELECT id,patient_id AS pid,game AS g,t,score,level,dur,ok,bad,pm,pa FROM sessions ORDER BY t")]);return send(res,200,{patients:p.rows,sessions:s.rows.map(x=>Object.assign({},x,{t:Number(x.t)}))})}
  if(u==="/api/patients"&&m==="POST"){const a=pat(await body(req));if(!a[0])return send(res,400,{error:"name"});r=await pool.query("INSERT INTO patients(name,age,gender,notes) VALUES($1,$2,$3,$4) RETURNING id",a);return send(res,200,{id:r.rows[0].id})}
  let k=u.match(/^\/api\/patients\/(\d+)$/);
  if(k&&m==="PUT"){const a=pat(await body(req));if(!a[0])return send(res,400,{error:"name"});await pool.query("UPDATE patients SET name=$2,age=$3,gender=$4,notes=$5 WHERE id=$1",[k[1],...a]);return send(res,200,{ok:true})}
  if(k&&m==="DELETE"){await pool.query("DELETE FROM patients WHERE id=$1",[k[1]]);return send(res,200,{ok:true})}
  if(u==="/api/sessions"&&m==="POST"){const b=await body(req);try{r=await pool.query(SINS,ses(N(b.pid),b))}catch(e){if(e.code==="23503")return send(res,400,{error:"patient"});throw e}return send(res,200,{id:r.rows[0].id})}
  k=u.match(/^\/api\/sessions\/(\d+)$/);
  if(k&&m==="DELETE"){await pool.query("DELETE FROM sessions WHERE id=$1",[k[1]]);return send(res,200,{ok:true})}
  if(u==="/api/import"&&m==="POST"){const b=await body(req);const P=Array.isArray(b.patients)?b.patients.slice(0,5000):[],S=Array.isArray(b.sessions)?b.sessions.slice(0,200000):[];
   const cl=await pool.connect();try{await cl.query("BEGIN");const map={};for(const p of P){const a=pat(p);if(!a[0])continue;map[p.id]=(await cl.query("INSERT INTO patients(name,age,gender,notes) VALUES($1,$2,$3,$4) RETURNING id",a)).rows[0].id}
   for(const x of S){if(map[x.pid])await cl.query(SINS,ses(map[x.pid],x))}await cl.query("COMMIT")}catch(e){await cl.query("ROLLBACK");throw e}finally{cl.release()}
   return send(res,200,{ok:true})}
  send(res,404,{error:"not_found"})
 }catch(e){console.error(e);if(!res.headersSent)send(res,e.message==="json"||e.message==="big"?400:500,{error:"server"})}
});
(async()=>{try{await pool.query(INIT);console.log("DB ready")}catch(e){console.error("DB init failed:",e.message)}
 server.listen(PORT,"0.0.0.0",()=>console.log("Listening on "+PORT))})();
process.on("SIGTERM",()=>{server.close(()=>pool.end().then(()=>process.exit(0)))});
