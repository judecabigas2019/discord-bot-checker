import express from "express";
import fetch from "node-fetch";
import nacl from "tweetnacl";
import bodyParser from "body-parser";
import https from "https";

const app = express();
const PUBLIC_KEY = process.env.DISCORD_PUBLIC_KEY;
const N8N_WEBHOOK = process.env.N8N_WEBHOOK;

// Agent to bypass self-signed certs
const insecureAgent = new https.Agent({ rejectUnauthorized: false });

// Capture raw body for signature verification
app.use(bodyParser.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString();
  }
}));

// Helper: hex → Uint8Array
function hexToUint8Array(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}

// Verify request signature
function verifySignature(req) {
  try {
    const signature = req.get("x-signature-ed25519");
    const timestamp = req.get("x-signature-timestamp");
    if (!signature || !timestamp) return false;

    const body = req.rawBody;
    return nacl.sign.detached.verify(
      Buffer.from(timestamp + body),
      hexToUint8Array(signature),
      hexToUint8Array(PUBLIC_KEY)
    );
  } catch (err) {
    console.error("❌ Signature verification error:", err);
    return false;
  }
}

// Forward payload to n8n
async function forwardToN8N(payload) {
  try {
    console.log("➡️ Forwarding to n8n:", N8N_WEBHOOK, "Payload:", payload);
    const res = await fetch(N8N_WEBHOOK, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      agent: insecureAgent
    });
    const text = await res.text();
    console.log("✅ n8n response:", res.status, text);
  } catch (err) {
    console.error("❌ Error forwarding to REMA AI:", err);
  }
}

app.post("/interactions", async (req, res) => {
  if (!verifySignature(req)) {
    console.log("⚠️ Bad request signature");
    return res.status(401).send("Bad request signature");
  }

  const interaction = req.body;

  if (interaction.type === 1) {
    console.log("💡 Ping received");
    return res.json({ type: 1 });
  }

  if (interaction.type === 2 && interaction.data.name === "audit") {
    const url = interaction.data.options[0].value;
    console.log("📥 /audit command received:", url);

    // Reply to Discord immediately
    res.json({
      type: 4,
      data: { content: `✅ Sent ${url} to REMA AI for audit!` }
    });

    // Forward asynchronously
    forwardToN8N({
      url,
      user: interaction.member?.user?.username,
      userId: interaction.member?.user?.id,
      channelId: interaction.channel_id,
      guildId: interaction.guild_id
    });
    return;
  }

  console.log("⚠️ Unknown command:", interaction.data?.name);
  return res.json({
    type: 4,
    data: { content: "❌ Unknown command." }
  });
});

app.listen(3000, () => console.log("🚀 Bot bridge running on port 3000"));
