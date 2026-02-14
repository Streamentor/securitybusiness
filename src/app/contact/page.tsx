import Link from "next/link";
import { Shield, Mail, MapPin, Building2 } from "lucide-react";

export default function ContactPage() {
  return (
    <div className="min-h-screen bg-gray-950">
      {/* Nav */}
      <nav className="border-b border-gray-800/50 bg-gray-950/80 backdrop-blur-xl">
        <div className="mx-auto max-w-4xl px-4 py-4 sm:px-6 lg:px-8">
          <Link href="/" className="flex items-center gap-2">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-emerald-500 to-cyan-500">
              <Shield className="h-5 w-5 text-white" />
            </div>
            <span className="text-xl font-bold">
              Secure<span className="bg-gradient-to-r from-emerald-400 via-cyan-400 to-blue-500 bg-clip-text text-transparent">SaaS</span>
            </span>
          </Link>
        </div>
      </nav>

      <main className="mx-auto max-w-4xl px-4 py-16 sm:px-6 lg:px-8">
        <h1 className="text-4xl font-bold text-white">Contact Us</h1>
        <p className="mt-3 text-lg text-gray-400">
          Have a question, feedback, or need support? We&apos;d love to hear from you.
        </p>

        <div className="mt-12 grid gap-6 sm:grid-cols-3">
          {/* Email Card */}
          <div className="rounded-2xl border border-gray-800 bg-gray-900/50 p-8 text-center transition hover:border-gray-700">
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-xl bg-emerald-500/10">
              <Mail className="h-7 w-7 text-emerald-400" />
            </div>
            <h2 className="mt-5 text-lg font-semibold text-white">Email</h2>
            <p className="mt-2 text-sm text-gray-400">Best way to reach us</p>
            <a
              href="mailto:stefan@scanmysaas.com"
              className="mt-4 inline-block text-emerald-400 hover:underline"
            >
              stefan@scanmysaas.com
            </a>
          </div>

          {/* Company Card */}
          <div className="rounded-2xl border border-gray-800 bg-gray-900/50 p-8 text-center transition hover:border-gray-700">
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-xl bg-cyan-500/10">
              <Building2 className="h-7 w-7 text-cyan-400" />
            </div>
            <h2 className="mt-5 text-lg font-semibold text-white">Company</h2>
            <p className="mt-2 text-sm text-gray-400">Legal entity</p>
            <p className="mt-4 text-gray-300">Content Petit LLC</p>
          </div>

          {/* Address Card */}
          <div className="rounded-2xl border border-gray-800 bg-gray-900/50 p-8 text-center transition hover:border-gray-700">
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-xl bg-blue-500/10">
              <MapPin className="h-7 w-7 text-blue-400" />
            </div>
            <h2 className="mt-5 text-lg font-semibold text-white">Address</h2>
            <p className="mt-2 text-sm text-gray-400">Registered office</p>
            <p className="mt-4 text-gray-300">
              16192 Coastal Highway<br />
              Lewes, Delaware 19958
            </p>
          </div>
        </div>

        {/* Response expectations */}
        <div className="mt-12 rounded-2xl border border-gray-800 bg-gray-900/50 p-8">
          <h2 className="text-xl font-semibold text-white">What to Expect</h2>
          <div className="mt-4 space-y-3 text-gray-300">
            <p>
              We aim to respond to all inquiries within <strong className="text-white">24 hours</strong> during business days. For urgent security-related matters, please include &quot;URGENT&quot; in your subject line.
            </p>
            <p>You can contact us about:</p>
            <ul className="mt-2 list-disc space-y-1 pl-6 text-gray-400">
              <li>Technical support and scanning issues</li>
              <li>Billing and subscription questions</li>
              <li>Feature requests and feedback</li>
              <li>Partnership and business inquiries</li>
              <li>Privacy and data-related requests</li>
              <li>Bug reports and security disclosures</li>
            </ul>
          </div>
        </div>
      </main>

      <footer className="border-t border-gray-800/50 py-8">
        <div className="mx-auto max-w-4xl px-4 text-center text-sm text-gray-500 sm:px-6 lg:px-8">
          &copy; {new Date().getFullYear()} Content Petit LLC. All rights reserved.
        </div>
      </footer>
    </div>
  );
}
