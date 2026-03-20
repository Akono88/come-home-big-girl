import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const VAPID_PUBLIC_KEY = Deno.env.get("VAPID_PUBLIC_KEY")!;
const VAPID_PRIVATE_KEY = Deno.env.get("VAPID_PRIVATE_KEY")!;
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

// Web Push crypto helpers
async function generatePushHeaders(subscription: { endpoint: string }, vapidPublicKey: string, vapidPrivateKey: string) {
  const audience = new URL(subscription.endpoint).origin;
  const expiry = Math.floor(Date.now() / 1000) + 12 * 60 * 60; // 12 hours

  const header = { typ: "JWT", alg: "ES256" };
  const payload = {
    aud: audience,
    exp: expiry,
    sub: "mailto:comehomebiggirl@noreply.com",
  };

  const b64url = (data: Uint8Array) =>
    btoa(String.fromCharCode(...data))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

  const b64urlStr = (str: string) =>
    b64url(new TextEncoder().encode(str));

  const headerB64 = b64urlStr(JSON.stringify(header));
  const payloadB64 = b64urlStr(JSON.stringify(payload));
  const unsignedToken = `${headerB64}.${payloadB64}`;

  // Import private key
  const privKeyBytes = Uint8Array.from(
    atob(vapidPrivateKey.replace(/-/g, "+").replace(/_/g, "/")),
    (c) => c.charCodeAt(0)
  );

  const cryptoKey = await crypto.subtle.importKey(
    "jwk",
    {
      kty: "EC",
      crv: "P-256",
      d: b64url(privKeyBytes),
      x: b64url(
        Uint8Array.from(
          atob(vapidPublicKey.replace(/-/g, "+").replace(/_/g, "/")),
          (c) => c.charCodeAt(0)
        ).slice(1, 33)
      ),
      y: b64url(
        Uint8Array.from(
          atob(vapidPublicKey.replace(/-/g, "+").replace(/_/g, "/")),
          (c) => c.charCodeAt(0)
        ).slice(33, 65)
      ),
    },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );

  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      cryptoKey,
      new TextEncoder().encode(unsignedToken)
    )
  );

  const token = `${unsignedToken}.${b64url(signature)}`;

  return {
    Authorization: `vapid t=${token}, k=${vapidPublicKey}`,
    TTL: "86400",
  };
}

// Encrypt push payload using RFC 8291 (aes128gcm)
async function encryptPayload(subscription: { keys: { p256dh: string; auth: string } }, payloadText: string) {
  const payloadBytes = new TextEncoder().encode(payloadText);

  // Decode subscription keys
  const p256dhBytes = Uint8Array.from(
    atob(subscription.keys.p256dh.replace(/-/g, "+").replace(/_/g, "/")),
    (c) => c.charCodeAt(0)
  );
  const authBytes = Uint8Array.from(
    atob(subscription.keys.auth.replace(/-/g, "+").replace(/_/g, "/")),
    (c) => c.charCodeAt(0)
  );

  // Generate ephemeral ECDH key pair
  const localKeyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );

  const localPublicKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", localKeyPair.publicKey)
  );

  // Import subscriber's public key
  const subscriberKey = await crypto.subtle.importKey(
    "raw",
    p256dhBytes,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );

  // ECDH shared secret
  const sharedSecret = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "ECDH", public: subscriberKey },
      localKeyPair.privateKey,
      256
    )
  );

  // HKDF for auth info
  const authInfo = new Uint8Array([
    ...new TextEncoder().encode("WebPush: info\0"),
    ...p256dhBytes,
    ...localPublicKey,
  ]);

  const authHkdfKey = await crypto.subtle.importKey(
    "raw",
    authBytes,
    { name: "HKDF" },
    false,
    ["deriveBits"]
  );

  const ikm = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: sharedSecret, info: authInfo },
      authHkdfKey,
      256
    )
  );

  // Generate salt
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const ikmKey = await crypto.subtle.importKey(
    "raw",
    ikm,
    { name: "HKDF" },
    false,
    ["deriveBits"]
  );

  // Derive CEK
  const cekInfo = new TextEncoder().encode("Content-Encoding: aes128gcm\0");
  const cek = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: salt, info: cekInfo },
      ikmKey,
      128
    )
  );

  // Derive nonce
  const nonceInfo = new TextEncoder().encode("Content-Encoding: nonce\0");
  const nonce = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: salt, info: nonceInfo },
      ikmKey,
      96
    )
  );

  // Pad payload: payload + 0x02 delimiter
  const paddedPayload = new Uint8Array(payloadBytes.length + 1);
  paddedPayload.set(payloadBytes);
  paddedPayload[payloadBytes.length] = 2; // record delimiter

  // Encrypt with AES-128-GCM
  const aesKey = await crypto.subtle.importKey(
    "raw",
    cek,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce },
      aesKey,
      paddedPayload
    )
  );

  // Build aes128gcm header: salt(16) + rs(4) + idlen(1) + keyid(65) + encrypted
  const rs = new Uint8Array(4);
  new DataView(rs.buffer).setUint32(0, payloadBytes.length + 1 + 16 + 1); // record size
  const header = new Uint8Array([
    ...salt,
    ...rs,
    localPublicKey.length,
    ...localPublicKey,
  ]);

  const body = new Uint8Array(header.length + encrypted.length);
  body.set(header);
  body.set(encrypted, header.length);

  return body;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { title, body, tag, sender_device, url } = await req.json();

    const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

    // Get all push subscriptions except sender
    let query = sb.from("push_subscriptions").select("*");
    if (sender_device) {
      query = query.neq("device_id", sender_device);
    }
    const { data: subs, error } = await query;

    if (error) {
      console.error("DB error:", error);
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    if (!subs || subs.length === 0) {
      return new Response(JSON.stringify({ sent: 0, message: "No subscribers" }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const payload = JSON.stringify({ title, body, tag, url });
    const results = { sent: 0, failed: 0, removed: 0 };

    for (const sub of subs) {
      try {
        const subscription = sub.subscription;
        const headers = await generatePushHeaders(
          subscription,
          VAPID_PUBLIC_KEY,
          VAPID_PRIVATE_KEY
        );

        const encryptedPayload = await encryptPayload(subscription, payload);

        const resp = await fetch(subscription.endpoint, {
          method: "POST",
          headers: {
            ...headers,
            "Content-Type": "application/octet-stream",
            "Content-Encoding": "aes128gcm",
          },
          body: encryptedPayload,
        });

        if (resp.status === 201 || resp.status === 200) {
          results.sent++;
        } else if (resp.status === 404 || resp.status === 410) {
          // Subscription expired — remove it
          await sb.from("push_subscriptions").delete().eq("id", sub.id);
          results.removed++;
        } else {
          console.error(`Push failed for ${sub.id}: ${resp.status} ${await resp.text()}`);
          results.failed++;
        }
      } catch (pushErr) {
        console.error(`Push error for ${sub.id}:`, pushErr);
        results.failed++;
      }
    }

    return new Response(JSON.stringify(results), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    console.error("Function error:", err);
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
