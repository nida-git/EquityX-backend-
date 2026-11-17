# Business Backend

## Deploy to Vercel

1. Import the repository into Vercel and set the project root to `backend` if the repository contains other projects. Vercel detects the Express app from `server.js`; no custom `vercel.json` is needed.
2. Set the Node.js version to 20.19 or newer.
3. Add these environment variables in Vercel for each environment you deploy:

   - `MONGODB_URL`: your MongoDB connection string. Configure the database network rules to allow connections from your Vercel deployment.
   - `JWT_SECRET`: a private random secret of at least 32 characters. Generate one with `node -e "console.log(require('node:crypto').randomBytes(48).toString('base64url'))"`.
   - `CLIENT_ORIGINS`: comma-separated frontend origins, with no path or trailing slash (for example, `https://app.example.com,https://preview.example.com`).
   - `ADMIN_EMAIL` and `ADMIN_PASSWORD`: set both to create/maintain the initial admin account, or leave both unset. `ADMIN_NAME` is optional.

4. Deploy. The root route is a liveness check; `/api/health` checks that the database is available. The first API request in a serverless instance initializes the reusable MongoDB connection.

Do not commit `.env` or paste secrets into source files. For local setup, copy `.env.sample` to `.env`, fill in the values, then run `npm install`, `npm run dev`, `npm test`, and `npm run check`.

## Admin account

When both admin environment variables are set, the app ensures that account exists on database initialization. To create or update it manually from a machine with the backend `.env` configured, run `npm run seed:admin`.

## Notes

- Production CORS is restricted to `CLIENT_ORIGINS`; requests without an `Origin` header (such as server-to-server calls) are allowed.
- Vercel Functions can scale across instances. Use Vercel Firewall or a shared rate-limiting service if you need distributed request throttling; per-process memory limits do not provide reliable global rate limiting.
