import express from "express";
import fetch from "node-fetch";
import nacl from "tweetnacl";
import bodyParser from "body-parser";
import https from "https";

const app = express();
const PUBLIC_KEY = process.env.DISCORD_PUBLIC_KEY;
const N8N_WEBHOOK = process.env.N8N_WEBHOOK;

// Create an HTTPS agent that skips cert validation ONLY for n8n
const insecureAgent = new https.Agent({ rejectUnauthorized: false });

// Capture raw body for signature verification
app.use(bodyParser.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString();
  }
}));

// Helper: convert hex string → Uint8Array
function hexToUint8Array(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
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
    console.error("Signature verification error:", err);
    return false;
  }
}

app.post("/interactions", async (req, res) => {
  try {
    if (!verifySignature(req)) {
      return res.status(401).send("Bad request signature");
    }

    const interaction = req.body;

    // PING from Discord
    if (interaction.type === 1) {
      return res.json({ type: 1 });
    }

    // Slash command: /audit
    if (interaction.type === 2 && interaction.data.name === "audit") {
      const url = interaction.data.options[0].value;

      // ✅ Reply to Discord immediately
      res.json({
        type: 4,
        data: { content: `✅ Sent ${url} to REMA AI for audit!` }
      });

      // 🔄 Forward to n8n asynchronously, ignoring self-signed cert
      fetch(N8N_WEBHOOK, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url,
          user: interaction.member?.user?.username,
          userId: interaction.member?.user?.id,
          channelId: interaction.channel_id,
          guildId: interaction.guild_id
        }),
        agent: insecureAgent
      }).catch(err => console.error("Error forwarding to REMA AI:", err));

      return;
    }

    // Fallback
    return res.json({
      type: 4,
      data: { content: "❌ Unknown command." }
    });

  } catch (err) {
    console.error("Error handling interaction:", err);
    return res.status(500).send("Internal Server Error");
  }
});

app.listen(3000, () => console.log("Bot bridge running on port 3000"));
