import type { CloudChallenge, Env, StoredChallenge } from "./types";

interface ConsumeRequest {
  challengeId: string;
  nonce: string;
  expiresAt: string;
  rulesetVersion: number;
}

export interface ChallengeConsumeResult {
  ok: boolean;
  reason?: "MISSING" | "EXPIRED" | "REUSED" | "MISMATCH";
}

export class ChallengeStore {
  constructor(
    private readonly state: DurableObjectState,
    private readonly env: Env
  ) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== "POST") return Response.json({ error: "METHOD_NOT_ALLOWED" }, { status: 405 });
    if (url.pathname === "/create") return this.create(request);
    if (url.pathname === "/consume") return this.consume(request);
    return Response.json({ error: "NOT_FOUND" }, { status: 404 });
  }

  async alarm(): Promise<void> {
    await this.state.storage.deleteAll();
  }

  private async create(request: Request): Promise<Response> {
    const challenge = (await request.json()) as StoredChallenge;
    const existing = await this.state.storage.get<StoredChallenge>("challenge");
    if (existing !== undefined) return Response.json({ error: "ALREADY_EXISTS" }, { status: 409 });
    await this.state.storage.put("challenge", challenge);
    await this.state.storage.setAlarm(Date.parse(challenge.expiresAt) + 60_000);
    return Response.json({ ok: true });
  }

  private async consume(request: Request): Promise<Response> {
    const expected = (await request.json()) as ConsumeRequest;
    const result = await this.state.storage.transaction<ChallengeConsumeResult>(async (transaction) => {
      const stored = await transaction.get<StoredChallenge>("challenge");
      if (stored === undefined || stored.challengeId !== expected.challengeId) {
        return { ok: false, reason: "MISSING" };
      }
      if (stored.used) return { ok: false, reason: "REUSED" };
      if (Date.parse(stored.expiresAt) <= Date.now()) {
        await transaction.put("challenge", { ...stored, used: true });
        return { ok: false, reason: "EXPIRED" };
      }
      const matches =
        stored.nonce === expected.nonce &&
        stored.expiresAt === expected.expiresAt &&
        stored.rulesetVersion === expected.rulesetVersion;
      await transaction.put("challenge", { ...stored, used: true });
      return matches ? { ok: true } : { ok: false, reason: "MISMATCH" };
    });
    return Response.json(result);
  }
}

export async function persistChallenge(env: Env, challenge: StoredChallenge): Promise<void> {
  const id = env.CHALLENGES.idFromName(challenge.challengeId);
  const response = await env.CHALLENGES.get(id).fetch("https://challenge/create", {
    method: "POST",
    body: JSON.stringify(challenge)
  });
  if (!response.ok) throw new Error("Challenge storage failed");
}

export async function consumeChallenge(
  env: Env,
  challenge: CloudChallenge
): Promise<ChallengeConsumeResult> {
  const id = env.CHALLENGES.idFromName(challenge.challengeId);
  const response = await env.CHALLENGES.get(id).fetch("https://challenge/consume", {
    method: "POST",
    body: JSON.stringify({
      challengeId: challenge.challengeId,
      nonce: challenge.nonce,
      expiresAt: challenge.expiresAt,
      rulesetVersion: challenge.rulesetVersion
    })
  });
  if (!response.ok) throw new Error("Challenge consumption failed");
  return response.json<ChallengeConsumeResult>();
}
