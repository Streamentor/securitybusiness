# SecureSaaS - Website Security Scanner

A full-stack SaaS platform that crawls websites and identifies security vulnerabilities, built for SaaS builders who want to ensure their applications are secure.

## Tech Stack

- **Framework**: Next.js 16 (App Router)
- **Language**: TypeScript
- **Styling**: Tailwind CSS 4
- **Database**: SQLite via Prisma ORM 7
- **Auth**: NextAuth.js v5 (Auth.js)
- **Animations**: Framer Motion
- **Icons**: Lucide React
- **HTML Parsing**: Cheerio

## Features

- **Landing Page** — Beautiful, animated landing page with hero scanner, features, pricing, and CTA sections
- **Free Website Scanner** — Scan any website for security vulnerabilities without signing up
- **Full Site Crawl** — Crawls up to 10 pages per scan to find vulnerabilities across the entire site
- **Security Checks**:
  - SSL/TLS certificate verification
  - HTTP to HTTPS redirect detection
  - Security headers analysis (CSP, HSTS, X-Frame-Options, etc.)
  - XSS pattern detection (unsafe JavaScript)
  - CSRF protection verification
  - Cookie security analysis (HttpOnly, Secure, SameSite)
  - Information disclosure detection (Server headers, X-Powered-By)
  - Mixed content detection
- **Security Score** — 0-100 score based on vulnerabilities found
- **Detailed Reports** — Each vulnerability includes severity, description, and actionable remediation steps
- **User Authentication** — Sign up/login to save scan history
- **Dashboard** — View all past scans and their results
- **Pricing Plans** — Free, Starter ($19/mo), Pro ($49/mo) tiers

## Getting Started

### Prerequisites

- Node.js 18+
- npm

### Installation

```bash
# Install dependencies
npm install

# Generate Prisma client
npx prisma generate

# Run database migrations
npx prisma migrate dev

# Start development server
npm run dev
```

The app will be available at [http://localhost:3000](http://localhost:3000).

### Environment Variables

Create a `.env` file with:

```env
DATABASE_URL="file:./dev.db"
AUTH_SECRET="your-secret-key-here"
NEXTAUTH_URL="http://localhost:3000"
```

## Project Structure

```
src/
├── app/
│   ├── api/
│   │   ├── auth/[...nextauth]/  # NextAuth API route
│   │   ├── register/            # User registration
│   │   └── scan/                # Scan API (create/list/get)
│   ├── dashboard/               # User dashboard
│   ├── login/                   # Login page
│   ├── register/                # Register page
│   ├── scan/[id]/               # Scan results page
│   ├── globals.css              # Global styles
│   ├── layout.tsx               # Root layout
│   └── page.tsx                 # Landing page
├── generated/prisma/            # Generated Prisma client
└── lib/
    ├── auth.ts                  # NextAuth configuration
    ├── db.ts                    # Prisma client singleton
    ├── scanner.ts               # Security scanning engine
    └── utils.ts                 # Utility functions
prisma/
├── schema.prisma                # Database schema
└── migrations/                  # Database migrations
```

## Scripts

- `npm run dev` — Start development server
- `npm run build` — Build for production
- `npm run start` — Start production server
- `npx prisma studio` — Open Prisma Studio (database GUI)
- `npx prisma migrate dev` — Run migrations
- `npx prisma generate` — Regenerate Prisma client
