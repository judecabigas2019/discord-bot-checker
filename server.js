import express from "express";
import fetch from "node-fetch";
import nacl from "tweetnacl";
import bodyParser from "body-parser";

const app = express();
const PUBLIC_KEY = process.env.DISCORD_PUBLIC_KEY;
const N8N_WEBHOOK = process.env.N8N_WEBHOOK;

// Capture raw body for signature verification
app.use(bodyParser.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString();
  }
}));

function verifySignature(req) {
  const signature = req.get("x-signature-ed25519");
  const timestamp = req.get("x-signature-timestamp");
  const body = req.rawBody;

  return nacl.sign.detached.verify(
    Buffer.from(timestamp + body),
    Buffer.from(signature, "hex"),
    Buffer.from(PUBLIC_KEY, "hex")
  );
}

app.post("/interactions", async (req, res) => {
  if (!verifySignature(req)) return res.status(401).send("Bad request signature");

  const interaction = req.body;

  if (interaction.type === 1) {
    // PING
    return res.json({ type: 1 });
  }

  if (interaction.type === 2 && interaction.data.name === "audit") {
    const url = interaction.data.options[0].value;

    // Forward to n8n
    await fetch(N8N_WEBHOOK, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        user: interaction.member.user.username,
        userId: interaction.member.user.id,
        channelId: interaction.channel_id,
        guildId: interaction.guild_id
      })
    });

    // Immediate reply to Discord
    return res.json({
      type: 4,
      data: { content: `✅ Sent ${url} to n8n for audit!` }
    });
  }
});

app.listen(3000, () => console.log("Bot bridge running on port 3000"));
