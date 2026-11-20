

const T = {
  properties:["name","address","property_type","notes"],
  units:["property_id","unit_name","rent_amount","status","notes"],
  tenants:["full_name","phone","email","national_id","next_of_kin","next_of_kin_phone","address","notes"],
  leases:["tenant_id","unit_id","start_date","end_date","monthly_rent","due_day","deposit_amount","status","notes"],
  payments:["lease_id","amount","payment_date","period_month","method","reference_no","received_by","notes"],
  expenses:["property_id","expense_date","category","description","amount","paid_to"],
  maintenance:["unit_id","tenant_id","title","description","priority","status","request_date","cost"]
};

const TABLE = {maintenance:"maintenance_requests"};

const json = (data,status=200,headers={}) =>
  new Response(JSON.stringify(data),{
    status,
    headers:{"content-type":"application/json",...headers}
  });

const err = (message,status=400) => json({error:message},status);
const te = new TextEncoder();

const b64 = data =>
  btoa(String.fromCharCode(...new Uint8Array(data)))
    .replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");

const un64 = value =>
  Uint8Array.from(
    atob(value.replace(/-/g,"+").replace(/_/g,"/")+"===".slice((value.length+3)%4)),
    c=>c.charCodeAt(0)
  );

async function mac(secret,value) {
  if(!secret) throw new Error("SESSION_SECRET missing");
  const key=await crypto.subtle.importKey(
    "raw",te.encode(secret),
    {name:"HMAC",hash:"SHA-256"},false,["sign"]
  );
  return b64(await crypto.subtle.sign("HMAC",key,te.encode(value)));
}

async function hash(password,salt=b64(crypto.getRandomValues(new Uint8Array(16)))) {
  const key=await crypto.subtle.importKey(
    "raw",te.encode(password),"PBKDF2",false,["deriveBits"]
  );
  const result=await crypto.subtle.deriveBits(
    {name:"PBKDF2",salt:un64(salt),iterations:150000,hash:"SHA-256"},
    key,256
  );
  return salt+"."+b64(result);
}

async function session(user,env) {
  const payload=b64(te.encode(JSON.stringify({
    ...user,
    exp:Date.now()+604800000
  })));
  return payload+"."+await mac(env.SESSION_SECRET,payload);
}

async function who(request,env) {
  const cookie=request.headers.get("Cookie")||"";
  const value=cookie.split(";")
    .map(x=>x.trim())
    .find(x=>x.startsWith("hizway="))?.slice(7);

  if(!value) return null;

  const [payload,signature]=value.split(".");
  if(!payload||!signature) return null;

  try {
    if(signature!==await mac(env.SESSION_SECRET,payload)) return null;
    const user=JSON.parse(new TextDecoder().decode(un64(payload)));
    return user.exp>Date.now()?user:null;
  } catch {
    return null;
  }
}

const cookie=value =>
  `hizway=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${value?604800:0}`;

const read=async request=>{
  try{return await request.json();}
  catch{return {};}
};

const num=value=>Number.isFinite(Number(value))?Number(value):0;

async function api(request,env) {
  const url=new URL(request.url);
  const path=url.pathname;
  const method=request.method;
  let body;

  if(path==="/api/health")
  return json({
    ok:true,
    service:"Hizway API",
    sessionConfigured:Boolean(env.SESSION_SECRET),
    databaseConfigured:Boolean(env.DB)
  });

  // ONE-TIME FIRST ADMINISTRATOR SETUP
  if(path==="/api/setup/admin"&&method==="POST") {
    body=await read(request);

    if(!env.ADMIN_SETUP_SECRET||
       String(body.setupSecret||"")!==env.ADMIN_SETUP_SECRET)
      return err("Invalid administrator setup secret.",403);

    const name=String(body.name||"").trim();
    const email=String(body.email||"").trim().toLowerCase();
    const password=String(body.password||"");

    if(name.length<2||!email.includes("@")||password.length<8)
      return err("Enter a valid name, email and password of at least 8 characters.");

    if(!env.SESSION_SECRET)
      return err("Session configuration is missing.",500);

    try {
      const passwordHash=await hash(password);

      const result=await env.DB.prepare(`
        INSERT INTO users(name,email,phone,password_hash,role)
        SELECT ?,?,?,?,'admin'
        WHERE NOT EXISTS(SELECT 1 FROM users)
      `).bind(name,email,String(body.phone||""),passwordHash).run();

      if(!result.meta.changes)
        return err("Administrator setup is closed. An account already exists.",409);

      const user={
        id:result.meta.last_row_id,
        name,
        email,
        role:"admin"
      };

      return json({user},201,{
        "set-cookie":cookie(await session(user,env))
      });
    } catch(error) {
      return err("Administrator creation failed. Check database configuration.",500);
    }
  }

  // LANDLORD REGISTRATION
  if(path==="/api/auth/register"&&method==="POST") {
    body=await read(request);

    const name=String(body.name||"").trim();
    const email=String(body.email||"").trim().toLowerCase();
    const password=String(body.password||"");

    if(name.length<2||!email.includes("@")||password.length<8)
      return err("Enter your name, valid email and password of at least 8 characters.");

    if(!env.SESSION_SECRET)
      return err("Session configuration is missing.",500);

    try {
      const result=await env.DB.prepare(`
        INSERT INTO users(name,email,phone,password_hash,role)
        VALUES(?,?,?,?, 'landlord')
      `).bind(name,email,String(body.phone||""),await hash(password)).run();

      const user={
        id:result.meta.last_row_id,
        name,
        email,
        role:"landlord"
      };

      return json({user},201,{
        "set-cookie":cookie(await session(user,env))
      });
    } catch(error) {
      if(/unique|constraint/i.test(String(error?.message||"")))
        return err("Email already registered.",409);

      return err("Registration failed. Check the database configuration.",500);
    }
  }

  // LOGIN
  if(path==="/api/auth/login"&&method==="POST") {
    body=await read(request);

    const email=String(body.email||"").trim().toLowerCase();
    const password=String(body.password||"");

    if(!email||!password)
      return err("Enter your email and password.");

    if(!env.SESSION_SECRET)
      return err("Session configuration is missing.",500);

    const account=await env.DB.prepare(
      "SELECT * FROM users WHERE email=?"
    ).bind(email).first();

    if(!account)
      return err("Incorrect email or password.",401);

    const [salt]=account.password_hash.split(".");
    const supplied=await hash(password,salt);

    if(supplied!==account.password_hash)
      return err("Incorrect email or password.",401);

    const user={
      id:account.id,
      name:account.name,
      email:account.email,
      role:account.role||"landlord"
    };

    return json({user},200,{
      "set-cookie":cookie(await session(user,env))
    });
  }

  // LOGOUT
  if(path==="/api/auth/logout") {
    return json({ok:true},200,{"set-cookie":cookie("")});
  }

  // AUTHENTICATION
  const user=await who(request,env);
  if(!user) return err("Please sign in again.",401);

  if(path==="/api/auth/me")
    return json({user});

  // ADMIN-ONLY API ROUTE
  if(path==="/api/admin/users") {
    if(user.role!=="admin") return err("Administrator access required.",403);

    const result=await env.DB.prepare(
      "SELECT id,name,email,phone,role,created_at FROM users ORDER BY id DESC"
    ).all();

    return json(result.results);
  }

  // DASHBOARD STATISTICS
  if(path==="/api/dashboard") {
    const month=new Date().toISOString().slice(0,7)+"-01";

    const q=async(sql,...values)=>
      env.DB.prepare(sql).bind(...values).first();

    const [collected,due,occupied,totalUnits,reminders,recent]=
      await Promise.all([
        q("SELECT COALESCE(SUM(amount),0)n FROM payments WHERE user_id=? AND period_month=?",user.id,month),
        q("SELECT COALESCE(SUM(monthly_rent),0)n FROM leases WHERE user_id=? AND status='active'",user.id),
        q("SELECT COUNT(*)n FROM units WHERE user_id=? AND status='occupied'",user.id),
        q("SELECT COUNT(*)n FROM units WHERE user_id=?",user.id),
        q("SELECT COUNT(*)n FROM leases l WHERE l.user_id=? AND l.status='active' AND NOT EXISTS(SELECT 1 FROM payments p WHERE p.lease_id=l.id AND p.period_month=?)",user.id,month),
        env.DB.prepare(`
          SELECT p.*,t.full_name tenant_name,u.unit_name
          FROM payments p
          JOIN leases l ON l.id=p.lease_id
          JOIN tenants t ON t.id=l.tenant_id
          JOIN units u ON u.id=l.unit_id
          WHERE p.user_id=?
          ORDER BY p.id DESC LIMIT 8
        `).bind(user.id).all()
      ]);

    return json({
      collected:collected.n,
      due:due.n,
      arrears:Math.max(0,due.n-collected.n),
      occupied:occupied.n,
      totalUnits:totalUnits.n,
      reminders:reminders.n,
      recent:recent.results
    });
  }

  // RENT REMINDERS
  if(path==="/api/reminders") {
    const month=new Date().toISOString().slice(0,7)+"-01";

    const result=await env.DB.prepare(`
      SELECT l.id,l.monthly_rent,t.full_name,t.phone,u.unit_name,
      COALESCE((
        SELECT SUM(amount) FROM payments
        WHERE lease_id=l.id AND period_month=?
      ),0)paid
      FROM leases l
      JOIN tenants t ON t.id=l.tenant_id
      JOIN units u ON u.id=l.unit_id
      WHERE l.user_id=? AND l.status='active'
    `).bind(month,user.id).all();

    return json(
      result.results.map(x=>({
        ...x,
        balance:Math.max(0,x.monthly_rent-x.paid)
      })).filter(x=>x.balance>0)
    );
  }

  // MATCH RENTAL MANAGEMENT ROUTES
  const match=path.match(
    /^\/api\/(properties|units|tenants|leases|payments|expenses|maintenance)(?:\/(\d+))?$/
  );

  if(!match) return err("Not found.",404);

  const key=match[1];
  const id=Number(match[2]||0);
  const table=TABLE[key]||key;
  const fields=T[key];

  // READ RECORDS
  if(method==="GET") {
    if(id) {
      const record=await env.DB.prepare(
        `SELECT * FROM ${table} WHERE id=? AND user_id=?`
      ).bind(id,user.id).first();

      return record?json(record):err("Not found.",404);
    }

    const queries={
      properties:`
        SELECT * FROM properties
        WHERE user_id=? ORDER BY id DESC
      `,
      units:`
        SELECT u.*,p.name property_name
        FROM units u
        JOIN properties p ON p.id=u.property_id
        WHERE u.user_id=? ORDER BY u.id DESC
      `,
      tenants:`
        SELECT * FROM tenants
        WHERE user_id=? ORDER BY full_name
      `,
      leases:`
        SELECT l.*,t.full_name tenant_name,t.phone,
        u.unit_name,p.name property_name
        FROM leases l
        JOIN tenants t ON t.id=l.tenant_id
        JOIN units u ON u.id=l.unit_id
        JOIN properties p ON p.id=u.property_id
        WHERE l.user_id=? ORDER BY l.id DESC
      `,
      payments:`
        SELECT p.*,t.full_name tenant_name,u.unit_name
        FROM payments p
        JOIN leases l ON l.id=p.lease_id
        JOIN tenants t ON t.id=l.tenant_id
        JOIN units u ON u.id=l.unit_id
        WHERE p.user_id=? ORDER BY p.id DESC
      `,
      expenses:`
        SELECT x.*,p.name property_name
        FROM expenses x
        LEFT JOIN properties p ON p.id=x.property_id
        WHERE x.user_id=? ORDER BY x.id DESC
      `,
      maintenance:`
        SELECT m.*,u.unit_name,t.full_name tenant_name
        FROM maintenance_requests m
        LEFT JOIN units u ON u.id=m.unit_id
        LEFT JOIN tenants t ON t.id=m.tenant_id
        WHERE m.user_id=? ORDER BY m.id DESC
      `
    };

    const result=await env.DB.prepare(queries[key])
      .bind(user.id).all();

    return json(result.results);
  }

  // CREATE RECORDS
  if(method==="POST") {
    body=await read(request);

    const required={
      properties:["name","address"],
      units:["property_id","unit_name"],
      tenants:["full_name","phone"],
      leases:["tenant_id","unit_id","start_date","monthly_rent"],
      payments:["lease_id","amount","payment_date","period_month"],
      expenses:["expense_date","category","description","amount"],
      maintenance:["title","request_date"]
    };

    for(const field of required[key]) {
      if(body[field]===undefined||body[field]==="") {
        return err(field+" is required.");
      }
    }

    const defaults={
      rent_amount:0,
      status:key==="units"?"vacant":
        key==="leases"?"active":"open",
      due_day:1,
      deposit_amount:0,
      method:"cash",
      received_by:user.name,
      priority:"normal",
      cost:0
    };

    const values=fields.map(field=>
      body[field]??(defaults[field]??null)
    );

    for(const field of ["amount","rent_amount","monthly_rent","cost"]) {
      if(field in body&&num(body[field])<0)
        return err("Amount cannot be negative.");
    }

    const columns=["user_id",...fields];

    try {
      const result=await env.DB.prepare(
        `INSERT INTO ${table}(${columns.join(",")})
         VALUES(${columns.map(()=>"?").join(",")})`
      ).bind(user.id,...values).run();

      if(key==="leases"&&body.status!=="ended") {
        await env.DB.prepare(
          "UPDATE units SET status='occupied' WHERE id=? AND user_id=?"
        ).bind(body.unit_id,user.id).run();
      }

      return json({ok:true,id:result.meta.last_row_id},201);

    } catch(error) {
      return err("Could not save record. Check related records and required fields.",400);
    }
  }

  // UPDATE MAINTENANCE
  if(method==="PATCH"&&id&&key==="maintenance") {
    body=await read(request);

    const result=await env.DB.prepare(`
      UPDATE maintenance_requests
      SET status=?,cost=?
      WHERE id=? AND user_id=?
    `).bind(
      body.status||"open",
      num(body.cost),
      id,
      user.id
    ).run();

    return result.meta.changes
      ?json({ok:true})
      :err("Maintenance record not found.",404);
  }

  // DELETE RECORDS
  if(method==="DELETE"&&id&&
    ["properties","units","tenants","expenses"].includes(key)) {

    try {
      const result=await env.DB.prepare(
        `DELETE FROM ${table} WHERE id=? AND user_id=?`
      ).bind(id,user.id).run();

      return result.meta.changes
        ?json({ok:true})
        :err("Not found.",404);

    } catch(error) {
      return err("Record is linked to other records.",409);
    }
  }

  return err("Method not allowed.",405);
}


// CLOUDFLARE WORKER ENTRY POINT
export default {
  async fetch(request,env) {
    if(new URL(request.url).pathname.startsWith("/api/")) {
      try {
        return await api(request,env);
      } catch(error) {
        return err("Worker error. Check D1 binding and server secrets.",500);
      }
    }

    return env.ASSETS.fetch(request);
  }
};
