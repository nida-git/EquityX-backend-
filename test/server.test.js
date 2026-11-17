import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { once } from "node:events";
import mongoose from "mongoose";

process.env.JWT_SECRET ||= "test-only-secret-that-is-long-enough";

const { default: app } = await import("../server.js");
let server;
let baseUrl;

before(async () => {
  server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  if (server) {
    server.close();
    await once(server, "close");
  }
  await mongoose.disconnect();
});

test("exports an Express app that serves the liveness route", async () => {
  const response = await fetch(baseUrl);

  assert.equal(response.status, 200);
  assert.equal(await response.text(), "Business Backend is running");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
});

test("returns JSON for malformed request payloads", async () => {
  const response = await fetch(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: "{",
  });

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    message: "Invalid request payload.",
  });
});

test("returns a JSON 404 for unknown routes", async () => {
  const response = await fetch(`${baseUrl}/unknown`);

  assert.equal(response.status, 404);
  assert.deepEqual(await response.json(), { message: "Not found." });
});
