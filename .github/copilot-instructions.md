## SecureSaaS - Workspace Instructions

- This is a Next.js 16 project with TypeScript and Tailwind CSS 4
- Uses App Router (all routes in `src/app/`)
- Database: SQLite via Prisma ORM 7 with driver adapter (`@prisma/adapter-better-sqlite3`)
- Auth: NextAuth.js v5 (Auth.js) with credentials provider
- After changing `prisma/schema.prisma`, run `npx prisma migrate dev` then `npx prisma generate`
- The Prisma client is generated to `src/generated/prisma/` — import from `@/generated/prisma/client`
- The security scanner engine is in `src/lib/scanner.ts` — it crawls sites and checks for vulnerabilities
- API routes are in `src/app/api/` — scan, register, and auth endpoints
- Use `framer-motion` for animations and `lucide-react` for icons
- All styling uses Tailwind CSS utility classes with a dark theme (gray-950 background, emerald/cyan accent gradient)
