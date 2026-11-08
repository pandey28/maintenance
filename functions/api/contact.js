// Cloudflare Worker: contact form -> Turnstile check -> FormSubmit -> your inbox
// Required settings in Cloudflare (Workers > your worker > Settings > Variables and Secrets):
//   TURNSTILE_SECRET_KEY  (type: Secret)  -> the SECRET key from Cloudflare Turnstile
//   FORM_SUBMIT_EMAIL     (type: Text)    -> pandeyashish2056@gmail.com

// Websites allowed to call this Worker (your real domain, not github.io)
const ALLOWED_ORIGINS = [
  "https://www.ashishpandey.com.np",
  "https://ashishpandey.com.np"
];

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const allowed = ALLOWED_ORIGINS.includes(origin);

    const corsHeaders = {
      "Access-Control-Allow-Origin": allowed ? origin : ALLOWED_ORIGINS[0],
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Vary": "Origin"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: allowed ? 204 : 403, headers: corsHeaders });
    }
    if (!allowed) return json({ error: "Origin not allowed" }, 403, corsHeaders);
    if (request.method !== "POST") return json({ error: "Method not allowed" }, 405, corsHeaders);

    let data;
    try { data = await request.json(); }
    catch { return json({ error: "Invalid request" }, 400, corsHeaders); }

    const name = String(data.name || "").trim();
    const email = String(data.email || "").trim();
    const message = String(data.message || "").trim();
    const website = String(data.website || "").trim(); // honeypot
    const token = String(data.turnstileToken || "").trim();

    // Honeypot filled = bot. Pretend success.
    if (website) return json({ success: true }, 200, corsHeaders);

    if (
      !name || name.length > 100 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 ||
      !message || message.length > 5000 ||
      !token
    ) {
      return json({ error: "Please check the fields and security verification." }, 400, corsHeaders);
    }

    // Basic spam filters: no line breaks in name/email (header injection), and few links.
    const linkCount = (message.match(/https?:\/\/|www\./gi) || []).length;
    if (/[\r\n]/.test(name) || /[\r\n]/.test(email) || linkCount > 2 || /https?:\/\//i.test(name)) {
      return json({ error: "Your message looks like spam. Please remove extra links and try again." }, 400, corsHeaders);
    }

    // Verify Turnstile on the server
    const ip = request.headers.get("CF-Connecting-IP") || "";
    const verifyBody = new FormData();
    verifyBody.append("secret", env.TURNSTILE_SECRET_KEY);
    verifyBody.append("response", token);
    if (ip) verifyBody.append("remoteip", ip);

    let verification;
    try {
      const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
        method: "POST",
        body: verifyBody
      });
      verification = await r.json();
    } catch {
      return json({ error: "Security verification unavailable. Please try again." }, 503, corsHeaders);
    }
    if (!verification.success) {
      return json({ error: "Security check failed. Please try again." }, 403, corsHeaders);
    }

    // Send to FormSubmit
    const payload = {
      name,
      email,
      message,
      _subject: "New message from ashishpandey.com.np",
      _template: "table",
      _captcha: "false", // we already verified with Turnstile
      _replyto: email
    };

    let mailResponse;
    try {
      mailResponse = await fetch(
        "https://formsubmit.co/ajax/" + encodeURIComponent(env.FORM_SUBMIT_EMAIL),
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": "https://www.ashishpandey.com.np",
            "Referer": "https://www.ashishpandey.com.np/"
          },
          body: JSON.stringify(payload)
        }
      );
    } catch {
      return json({ error: "Email service unavailable. Please try again later." }, 502, corsHeaders);
    }

    let mailResult = {};
    try { mailResult = await mailResponse.json(); } catch {}
    if (!mailResponse.ok || !(mailResult.success === true || mailResult.success === "true")) {
      // This shows up in Workers > Logs, so you can see FormSubmit's real reply.
      console.log("FormSubmit rejected:", mailResponse.status, JSON.stringify(mailResult));
      return json({ error: "Email service did not accept the message. Please try again later." }, 502, corsHeaders);
    }

    return json({ success: true }, 200, corsHeaders);
  }
};

function json(body, status, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers }
  });
}
