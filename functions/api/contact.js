// Cloudflare Pages Function: handles POST /api/contact
// Needs 2 settings in Cloudflare Pages > your project > Settings > Variables and Secrets:
//   TURNSTILE_SECRET_KEY  (Secret) -> secret key from Cloudflare Turnstile
//   FORM_SUBMIT_EMAIL     (Text)   -> pandeyashish2056@gmail.com

const ALLOWED_ORIGINS = [
  "https://www.ashishpandey.com.np",
  "https://ashishpandey.com.np"
];

export async function onRequest(context) {
  const { request, env } = context;
  const origin = request.headers.get("Origin") || "";

  if (request.method !== "POST") return json({ error: "Method not allowed", message: "Method not allowed" }, 405);

  // Only your own website may use this form (the *.pages.dev preview address is allowed for testing)
  const sameSite = ALLOWED_ORIGINS.includes(origin) || origin.endsWith(".pages.dev");
  if (!sameSite) return json({ error: "Origin not allowed", message: "Origin not allowed" }, 403);

  let data;
  try { data = await request.json(); }
  catch { return json({ error: "Invalid request", message: "Invalid request" }, 400); }

  const name = String(data.name || "").trim();
  const email = String(data.email || "").trim();
  const message = String(data.message || "").trim();
  const website = String(data.website || "").trim(); // honeypot
  const token = String(data.turnstileToken || "").trim();

  // Honeypot filled = bot. Pretend success.
  if (website) return json({ success: true });

  if (
    !name || name.length > 100 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 ||
    !message || message.length > 5000 ||
    !token
  ) {
    return json({ error: "Please check the fields and security verification.", message: "Please check the fields and security verification." }, 400);
  }

  // Basic spam filters: no line breaks in name/email, max 2 links in the message
  const linkCount = (message.match(/https?:\/\/|www\./gi) || []).length;
  if (/[\r\n]/.test(name) || /[\r\n]/.test(email) || linkCount > 2 || /https?:\/\//i.test(name)) {
    return json({ error: "Looks like spam.", message: "Your message looks like spam. Please remove extra links." }, 400);
  }

  // Check the Cloudflare Turnstile token on the server
  const ip = request.headers.get("CF-Connecting-IP") || "";
  const verifyBody = new FormData();
  verifyBody.append("secret", env.TURNSTILE_SECRET_KEY);
  verifyBody.append("response", token);
  if (ip) verifyBody.append("remoteip", ip);

  let verification;
  try {
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: verifyBody });
    verification = await r.json();
  } catch {
    return json({ error: "Verification unavailable", message: "Security verification unavailable. Please try again." }, 503);
  }
  if (!verification.success) {
    const codes = (verification["error-codes"] || []).join(", ") || "no code";
    return json({ error: "Security check failed", message: "Security check failed: " + codes }, 403);
  }

  // Send to your email through FormSubmit
  const payload = {
    name, email, message,
    _subject: "New message from ashishpandey.com.np",
    _template: "table",
    _captcha: "false",
    _replyto: email
  };

  let mailResponse;
  try {
    mailResponse = await fetch("https://formsubmit.co/ajax/" + encodeURIComponent(env.FORM_SUBMIT_EMAIL), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Origin": "https://www.ashishpandey.com.np",
        "Referer": "https://www.ashishpandey.com.np/"
      },
      body: JSON.stringify(payload)
    });
  } catch {
    return json({ error: "Email service unavailable", message: "Email service unavailable. Please try again later." }, 502);
  }

  let mailResult = {};
  try { mailResult = await mailResponse.json(); } catch {}
  if (!mailResponse.ok || !(mailResult.success === true || mailResult.success === "true")) {
    console.log("FormSubmit rejected:", mailResponse.status, JSON.stringify(mailResult));
    return json({ error: "Email not accepted", message: "Email service did not accept the message. Please try again later." }, 502);
  }

  return json({ success: true });
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
  });
}
