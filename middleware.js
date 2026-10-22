// 접근 제한(전용 로그인 화면 + 로그인 쿠키).
// - 버셀 환경변수 ACCESS_USERS: 관리자가 승인해서 붙인 "이메일:솔트.해시"를 쉼표로 이어 붙인 값. 여기 있는 사람만 들어올 수 있다.
// - 로그인 없이 열리는 곳: /login.html, /apply.html, /__login(로그인 처리), /__logout.
// - 그 밖의 모든 파일은 로그인 쿠키가 있어야 한다. 쿠키가 없으면 페이지는 /login.html 로 보내고, 데이터 파일은 401.
// - 쿠키는 이메일+만료일을 그 사람의 저장된 해시로 서명한 값이라, 계정을 지우거나 비밀번호를 바꾸면 그 사람의 쿠키는 바로 무효가 된다.
// - 등록된 계정이 하나도 없으면 아무도 못 들어간다(실수로 열리는 것을 막기 위해).
import { next } from "@vercel/functions";

const ITER = 20000;                       // apply.html 과 같은 값이어야 한다
const COOKIE = "skr_session";
const DAYS = 30;                          // 로그인 유지 기간
const PUBLIC = new Set(["/login.html", "/login", "/apply.html", "/apply"]);

const enc = new TextEncoder();
const b64u = (u8) => btoa(String.fromCharCode.apply(null, u8)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64u = (s) => { s = String(s).replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)); };

const json = (obj, status, extra) => new Response(JSON.stringify(obj), { status, headers: Object.assign({ "Cache-Control": "no-store", "Content-Type": "application/json; charset=utf-8" }, extra || {}) });
const plain = (msg, status) => new Response(msg, { status, headers: { "Cache-Control": "no-store", "Content-Type": "text/plain; charset=utf-8" } });
const to = (location) => new Response(null, { status: 302, headers: { Location: location, "Cache-Control": "no-store" } });

// 길이가 같은 값끼리 끝까지 비교(비교 시간으로 추측하지 못하게)
const same = (a, b) => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
};

async function pbkdf2(password, salt) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: ITER }, key, 256));
}

async function sign(keyBytes, message) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(message)));
}

function accounts() {
  const map = {};
  String(process.env.ACCESS_USERS || "").split(",").map((s) => s.trim()).filter(Boolean).forEach((s) => {
    const i = s.indexOf(":"), j = s.indexOf(".", i + 1);
    if (i > 0 && j > i + 1) map[s.slice(0, i).toLowerCase()] = [s.slice(i + 1, j), s.slice(j + 1)];   // 이메일 → [솔트, 해시]
  });
  return map;
}

async function verifyPassword(entry, password) {
  try {
    if (!entry) { await pbkdf2(password, enc.encode("dummy-salt-value")); return false; }   // 없는 계정도 같은 시간이 걸리게
    return same(await pbkdf2(password, fromB64u(entry[0])), fromB64u(entry[1]));
  } catch (e) { return false; }
}

async function makeToken(email, entry) {
  const body = b64u(enc.encode(JSON.stringify({ e: email, x: Date.now() + DAYS * 86400000 })));
  return body + "." + b64u(await sign(fromB64u(entry[1]), body));
}

async function tokenOk(token, users) {
  try {
    const [body, sig] = String(token).split(".");
    if (!body || !sig) return false;
    const p = JSON.parse(new TextDecoder().decode(fromB64u(body)));
    const entry = users[String(p.e || "").toLowerCase()];
    if (!entry || !(p.x > Date.now())) return false;
    return same(await sign(fromB64u(entry[1]), body), fromB64u(sig));
  } catch (e) { return false; }
}

const getCookie = (request) => {
  const m = (request.headers.get("cookie") || "").match(new RegExp("(?:^|;\\s*)" + COOKIE + "=([^;]+)"));
  return m ? m[1] : "";
};

const safeNext = (n) => (typeof n === "string" && n.startsWith("/") && !n.startsWith("//") && !n.startsWith("/__") && !n.includes("\\") ? n : "/index.html");

export default async function middleware(request) {
  const url = new URL(request.url), path = url.pathname;

  // 로그아웃: 쿠키를 지우고 로그인 화면으로
  if (path === "/__logout") {
    return new Response(null, { status: 302, headers: { Location: "/login.html", "Cache-Control": "no-store", "Set-Cookie": COOKIE + "=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax" } });
  }

  const users = accounts();

  // 로그인 처리: 메일+비밀번호가 맞으면 쿠키를 준다
  if (path === "/__login") {
    if (request.method !== "POST") return plain("POST only", 405);
    if (!Object.keys(users).length) return json({ ok: false, error: "접근 계정이 설정되지 않았습니다. 관리자에게 문의하세요." }, 503);
    let email = "", password = "";
    try { const b = await request.json(); email = String(b.email || "").trim().toLowerCase(); password = String(b.password || ""); } catch (e) { return json({ ok: false, error: "요청 형식이 올바르지 않습니다." }, 400); }
    const entry = users[email];
    if (await verifyPassword(entry, password)) {
      const token = await makeToken(email, entry);
      return json({ ok: true }, 200, { "Set-Cookie": COOKIE + "=" + token + "; Path=/; Max-Age=" + DAYS * 86400 + "; HttpOnly; Secure; SameSite=Lax" });
    }
    await new Promise((r) => setTimeout(r, 400));                       // 비밀번호를 연달아 시도하는 속도를 늦춘다
    return json({ ok: false, error: "메일 또는 비밀번호가 틀렸거나 아직 승인되지 않았습니다." }, 401);
  }

  if (PUBLIC.has(path)) return next();
  if (Object.keys(users).length && (await tokenOk(getCookie(request), users))) return next();

  // 로그인 안 됨: 페이지 이동이면 로그인 화면으로, 파일(데이터) 요청이면 401
  const wantsPage = request.method === "GET" && (path === "/" || path.endsWith(".html") || (request.headers.get("accept") || "").includes("text/html"));
  if (wantsPage) return to("/login.html?next=" + encodeURIComponent(safeNext(path === "/" ? "/index.html" : path + url.search)));
  return plain("로그인이 필요합니다.", 401);
}
