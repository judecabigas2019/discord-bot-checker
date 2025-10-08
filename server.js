import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";

const app = express();
app.use(express.json());

const PUBLIC_KEY = process.env.DISCORD_PUBLIC_KEY;
const N8N_WEBHOOK = process.env.N8N_WEBHOOK; // e.g. https://your-n8n.coolify.app/webhook/audit

// Discord signature verification
function verifySignature(req) {
  const signature = req.get("x-signature-ed25519");
  const timestamp = req.get("x-signature-timestamp");
  const body = JSON.stringify(req.body);

  const isVerified = crypto.verify(
    "ed25519",
    Buffer.from(timestamp + body),
    Buffer.from(PUBLIC_KEY, "hex"),
    Buffer.from(signature, "hex")
  );
  return isVerified;
}

app.post("/interactions", async (req, res) => {
  if (!verifySignature(req)) return res.status(401).send("Bad request signature");

  const interaction = req.body;

  if (interaction.type === 1) {
    // Ping
    return res.json({ type: 1 });
  }

  if (interaction.type === 2 && interaction.data.name === "audit") {
    const url = interaction.data.options[0].value;

    // Forward to n8n webhook
    await fetch(N8N_WEBHOOK, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, user: interaction.member.user.username })
    });

    return res.json({
      type: 4,
      data: { content: `✅ Sent ${url} to n8n for audit!` }
    });
  }
});

app.listen(3000, () => console.log("Bot bridge running on port 3000"));
