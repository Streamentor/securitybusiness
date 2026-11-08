import { NextRequest } from "next/server";
import { verifySnsMessage, handleSnsMessage } from "@/lib/email/sns";
export const maxDuration = 30;
export async function POST(req: NextRequest) {
  if (Number(req.headers.get("content-length")) > 262_144) return new Response(null, { status: 413 });
  let message;
  try {
    const reader = req.body?.getReader(); if (!reader) return new Response(null, { status: 400 });
    const chunks: Uint8Array[] = []; let size = 0;
    try { while (true) { const { done, value } = await reader.read(); if (done) break; size += value.length; if (size > 262_144) return new Response(null, { status: 413 }); chunks.push(value); } } finally { await reader.cancel(); }
    message = await verifySnsMessage(JSON.parse(Buffer.concat(chunks).toString("utf8")));
  } catch { return new Response(null, { status: 400 }); }
  try { await handleSnsMessage(message); return new Response(null, { status: 200 }); }
  catch { console.error("SES event processing failed"); return new Response(null, { status: 503 }); }
}
