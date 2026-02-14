import Link from "next/link";
import { Shield } from "lucide-react";

export default function PrivacyPolicyPage() {
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
        <h1 className="text-4xl font-bold text-white">Privacy Policy</h1>
        <p className="mt-2 text-sm text-gray-500">Last updated: February 14, 2026</p>

        <div className="prose-invert mt-10 space-y-8 text-gray-300 leading-relaxed">
          <section>
            <h2 className="text-xl font-semibold text-white">1. Introduction</h2>
            <p className="mt-3">
              Content Petit LLC (&quot;Company,&quot; &quot;we,&quot; &quot;us,&quot; or &quot;our&quot;), located at 16192 Coastal Highway, Lewes, Delaware, operates the SecureSaaS website vulnerability scanning platform at scanmysaas.com (&quot;Service&quot;). This Privacy Policy explains how we collect, use, disclose, and safeguard your information when you visit our website or use our Service.
            </p>
            <p className="mt-3">
              By using our Service, you agree to the collection and use of information in accordance with this Privacy Policy. If you do not agree with the terms of this Privacy Policy, please do not access the Service.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">2. Information We Collect</h2>

            <h3 className="mt-4 text-lg font-medium text-gray-200">2.1 Personal Information</h3>
            <p className="mt-2">When you register for an account or use our Service, we may collect:</p>
            <ul className="mt-2 list-disc space-y-1 pl-6">
              <li>Name and email address</li>
              <li>Account credentials (password is stored in hashed form)</li>
              <li>Billing information processed through Stripe (we do not store credit card numbers)</li>
              <li>URLs of websites you submit for scanning</li>
            </ul>

            <h3 className="mt-4 text-lg font-medium text-gray-200">2.2 Automatically Collected Information</h3>
            <p className="mt-2">When you access our Service, we may automatically collect:</p>
            <ul className="mt-2 list-disc space-y-1 pl-6">
              <li>IP address and browser type</li>
              <li>Device information and operating system</li>
              <li>Pages visited and time spent on pages</li>
              <li>Referring website addresses</li>
              <li>Cookies and similar tracking technologies</li>
            </ul>

            <h3 className="mt-4 text-lg font-medium text-gray-200">2.3 Scan Data</h3>
            <p className="mt-2">
              When you use our vulnerability scanning Service, we collect and process information about the target websites you scan, including discovered vulnerabilities, security headers, SSL configurations, and other security-related findings. This data is stored to provide you with scan reports and history.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">3. How We Use Your Information</h2>
            <p className="mt-3">We use the information we collect to:</p>
            <ul className="mt-2 list-disc space-y-1 pl-6">
              <li>Provide, maintain, and improve our vulnerability scanning Service</li>
              <li>Create and manage your account</li>
              <li>Process transactions and send related billing information</li>
              <li>Generate vulnerability scan reports</li>
              <li>Send you technical notices, updates, and security alerts</li>
              <li>Respond to your comments, questions, and support requests</li>
              <li>Monitor and analyze usage trends to improve user experience</li>
              <li>Detect, prevent, and address technical issues and abuse</li>
            </ul>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">4. Data Sharing and Disclosure</h2>
            <p className="mt-3">We do not sell your personal information. We may share information in the following situations:</p>
            <ul className="mt-2 list-disc space-y-1 pl-6">
              <li><strong className="text-white">Service Providers:</strong> We share data with third-party vendors who assist in operating our Service (e.g., Stripe for payment processing, hosting providers for infrastructure).</li>
              <li><strong className="text-white">Legal Requirements:</strong> We may disclose information if required to do so by law or in response to valid requests by public authorities.</li>
              <li><strong className="text-white">Business Transfers:</strong> In connection with a merger, acquisition, or sale of assets, your information may be transferred as a business asset.</li>
              <li><strong className="text-white">With Your Consent:</strong> We may share your information for any other purpose with your explicit consent.</li>
            </ul>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">5. Data Security</h2>
            <p className="mt-3">
              We implement appropriate technical and organizational security measures to protect your personal information, including encryption in transit (TLS/SSL), hashed passwords, and secure infrastructure. However, no method of transmission over the Internet or electronic storage is 100% secure, and we cannot guarantee absolute security.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">6. Data Retention</h2>
            <p className="mt-3">
              We retain your personal information for as long as your account is active or as needed to provide you with our Service. Scan results are retained in your account until you delete them or close your account. We may retain certain information as required by law or for legitimate business purposes.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">7. Cookies</h2>
            <p className="mt-3">
              We use cookies and similar tracking technologies to maintain your session, remember your preferences, and analyze how our Service is used. You can instruct your browser to refuse all cookies or indicate when a cookie is being sent. However, some features of the Service may not function properly without cookies.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">8. Third-Party Services</h2>
            <p className="mt-3">Our Service integrates with or uses the following third-party services, each with their own privacy policies:</p>
            <ul className="mt-2 list-disc space-y-1 pl-6">
              <li><strong className="text-white">Stripe</strong> — for payment processing</li>
              <li><strong className="text-white">Vercel</strong> — for hosting and infrastructure</li>
              <li><strong className="text-white">Supabase</strong> — for database services</li>
            </ul>
            <p className="mt-3">We encourage you to review the privacy policies of these third-party services.</p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">9. Your Rights</h2>
            <p className="mt-3">Depending on your location, you may have the following rights regarding your personal information:</p>
            <ul className="mt-2 list-disc space-y-1 pl-6">
              <li>Access, correct, or delete your personal information</li>
              <li>Object to or restrict the processing of your data</li>
              <li>Data portability — receive a copy of your data in a structured format</li>
              <li>Withdraw consent at any time where processing is based on consent</li>
              <li>Lodge a complaint with a supervisory authority</li>
            </ul>
            <p className="mt-3">To exercise any of these rights, please contact us at <a href="mailto:stefan@scanmysaas.com" className="text-emerald-400 hover:underline">stefan@scanmysaas.com</a>.</p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">10. Children&apos;s Privacy</h2>
            <p className="mt-3">
              Our Service is not intended for individuals under the age of 18. We do not knowingly collect personal information from children. If we become aware that we have collected personal data from a child without parental consent, we will take steps to remove that information.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">11. International Data Transfers</h2>
            <p className="mt-3">
              Your information may be transferred to and processed in countries other than your country of residence. These countries may have data protection laws that differ from those of your country. By using our Service, you consent to such transfers.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">12. Changes to This Privacy Policy</h2>
            <p className="mt-3">
              We may update this Privacy Policy from time to time. We will notify you of any changes by posting the new Privacy Policy on this page and updating the &quot;Last updated&quot; date. You are advised to review this Privacy Policy periodically for any changes.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">13. Contact Us</h2>
            <p className="mt-3">If you have any questions about this Privacy Policy, please contact us:</p>
            <div className="mt-3 rounded-xl border border-gray-800 bg-gray-900/50 p-6">
              <p><strong className="text-white">Content Petit LLC</strong></p>
              <p className="mt-1">16192 Coastal Highway</p>
              <p>Lewes, Delaware 19958</p>
              <p className="mt-2">Email: <a href="mailto:stefan@scanmysaas.com" className="text-emerald-400 hover:underline">stefan@scanmysaas.com</a></p>
            </div>
          </section>
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
