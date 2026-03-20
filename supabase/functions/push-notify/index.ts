import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import webPush from "npm:web-push@3.6.7";

const VAPID_PUBLIC_KEY = Deno.env.get("VAPID_PUBLIC_KEY")!;
const VAPID_PRIVATE_KEY = Deno.env.get("VAPID_PRIVATE_KEY")!;
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

webPush.setVapidDetails(
  "mailto:comehomebiggirl@noreply.com",
  VAPID_PUBLIC_KEY,
  VAPID_PRIVATE_KEY
);

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
};

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
      return new Response(
        JSON.stringify({ sent: 0, message: "No subscribers" }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const payload = JSON.stringify({ title, body, tag, url });
    const results = { sent: 0, failed: 0, removed: 0 };

    for (const sub of subs) {
      try {
        const subscription = sub.subscription;

        // Ensure subscription has the right shape for web-push
        const pushSub = {
          endpoint: subscription.endpoint,
          keys: {
            p256dh: subscription.keys.p256dh,
            auth: subscription.keys.auth,
          },
        };

        await webPush.sendNotification(pushSub, payload, { TTL: 86400 });
        results.sent++;
      } catch (pushErr: any) {
        console.error(`Push error for ${sub.id}:`, pushErr?.statusCode, pushErr?.body);
        if (pushErr?.statusCode === 404 || pushErr?.statusCode === 410) {
          // Subscription expired — remove it
          await sb.from("push_subscriptions").delete().eq("id", sub.id);
          results.removed++;
        } else {
          results.failed++;
        }
      }
    }

    return new Response(JSON.stringify(results), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err: any) {
    console.error("Function error:", err);
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
