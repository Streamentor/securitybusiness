import Link from "next/link";
import { Shield } from "lucide-react";

export default function TermsOfServicePage() {
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
        <h1 className="text-4xl font-bold text-white">Terms of Service</h1>
        <p className="mt-2 text-sm text-gray-500">Last updated: February 14, 2026</p>

        <div className="prose-invert mt-10 space-y-8 text-gray-300 leading-relaxed">
          <section>
            <h2 className="text-xl font-semibold text-white">1. Agreement to Terms</h2>
            <p className="mt-3">
              These Terms of Service (&quot;Terms&quot;) constitute a legally binding agreement between you and Content Petit LLC (&quot;Company,&quot; &quot;we,&quot; &quot;us,&quot; or &quot;our&quot;), located at 16192 Coastal Highway, Lewes, Delaware, governing your access to and use of the SecureSaaS website vulnerability scanning platform at scanmysaas.com (&quot;Service&quot;).
            </p>
            <p className="mt-3">
              By accessing or using our Service, you agree to be bound by these Terms. If you do not agree to these Terms, you must not use the Service.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">2. Description of Service</h2>
            <p className="mt-3">
              SecureSaaS is a web application vulnerability scanning platform that performs automated security assessments on websites. The Service crawls target websites and checks for common vulnerabilities, security misconfigurations, and best-practice violations including but not limited to SSL/TLS issues, missing security headers, cross-site scripting (XSS), cross-site request forgery (CSRF), and exposed sensitive files.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">3. Account Registration</h2>
            <p className="mt-3">To access certain features of the Service, you must create an account. You agree to:</p>
            <ul className="mt-2 list-disc space-y-1 pl-6">
              <li>Provide accurate, current, and complete information during registration</li>
              <li>Maintain and promptly update your account information</li>
              <li>Maintain the security of your password and accept all risks of unauthorized access</li>
              <li>Notify us immediately if you discover any unauthorized use of your account</li>
            </ul>
            <p className="mt-3">You are responsible for all activity that occurs under your account.</p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">4. Acceptable Use</h2>
            <p className="mt-3">You agree to use the Service only for lawful purposes. You must:</p>
            <ul className="mt-2 list-disc space-y-1 pl-6">
              <li><strong className="text-white">Only scan websites you own or have explicit written authorization to test.</strong></li>
              <li>Not use the Service to conduct attacks, exploit vulnerabilities, or cause damage to any website or system.</li>
              <li>Not use the Service in any way that violates applicable local, state, national, or international law.</li>
              <li>Not attempt to probe, scan, or test the vulnerability of our Service itself, or circumvent any security measures.</li>
              <li>Not use the Service to scan websites that host illegal content.</li>
              <li>Not resell, sublicense, or redistribute scan results for commercial purposes without our written consent.</li>
              <li>Not overload, impair, or disrupt the Service or servers connected to the Service.</li>
            </ul>
            <p className="mt-3">
              <strong className="text-white">Unauthorized scanning of third-party websites is strictly prohibited and may constitute a criminal offense.</strong> We reserve the right to suspend or terminate your account immediately if we suspect unauthorized scanning activity.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">5. Plans and Pricing</h2>
            <p className="mt-3">The Service offers the following plans:</p>
            <ul className="mt-2 list-disc space-y-1 pl-6">
              <li><strong className="text-white">Free Plan:</strong> Includes a limited number of scan credits with basic vulnerability reports.</li>
              <li><strong className="text-white">Starter Plan ($29/month):</strong> Includes additional scan credits, fix suggestions, and PDF report exports.</li>
              <li><strong className="text-white">Pro Plan ($79/month):</strong> Includes unlimited scans, priority scanning, API access, and dedicated support.</li>
            </ul>
            <p className="mt-3">
              Prices are subject to change. We will notify existing subscribers of any price changes at least 30 days before they take effect. All fees are non-refundable unless otherwise required by law.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">6. Payment and Billing</h2>
            <p className="mt-3">
              Paid subscriptions are billed in advance on a monthly basis through Stripe. By providing a payment method, you authorize us to charge the applicable fees. If payment fails, we may suspend access to paid features until payment is resolved.
            </p>
            <p className="mt-3">
              You may cancel your subscription at any time through your account dashboard or by contacting us. Cancellation takes effect at the end of the current billing period.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">7. Intellectual Property</h2>
            <p className="mt-3">
              The Service and its original content, features, and functionality are owned by Content Petit LLC and are protected by copyright, trademark, and other intellectual property laws. Our trademarks may not be used without our prior written consent.
            </p>
            <p className="mt-3">
              You retain ownership of any data you submit for scanning. We do not claim ownership over your scan results, but we may use aggregated, anonymized data to improve the Service.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">8. Disclaimer of Warranties</h2>
            <p className="mt-3">
              THE SERVICE IS PROVIDED &quot;AS IS&quot; AND &quot;AS AVAILABLE&quot; WITHOUT ANY WARRANTIES OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, OR ACCURACY.
            </p>
            <p className="mt-3">
              We do not warrant that the Service will detect all vulnerabilities in your web applications. The absence of reported vulnerabilities does not guarantee that your website is secure. Our scans are automated and may produce false positives or miss certain vulnerability types. The Service is not a substitute for professional penetration testing or security audits.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">9. Limitation of Liability</h2>
            <p className="mt-3">
              TO THE MAXIMUM EXTENT PERMITTED BY LAW, CONTENT PETIT LLC SHALL NOT BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES, OR ANY LOSS OF PROFITS OR REVENUES, WHETHER INCURRED DIRECTLY OR INDIRECTLY, OR ANY LOSS OF DATA, USE, GOODWILL, OR OTHER INTANGIBLE LOSSES RESULTING FROM:
            </p>
            <ul className="mt-2 list-disc space-y-1 pl-6">
              <li>Your use or inability to use the Service</li>
              <li>Any unauthorized access to or use of our servers and/or personal information stored therein</li>
              <li>Any vulnerabilities not detected by the Service</li>
              <li>Any security breaches or damages resulting from reliance on scan results</li>
              <li>Any third-party conduct or content on the Service</li>
            </ul>
            <p className="mt-3">
              Our total aggregate liability shall not exceed the amount you paid us in the twelve (12) months prior to the claim.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">10. Indemnification</h2>
            <p className="mt-3">
              You agree to indemnify, defend, and hold harmless Content Petit LLC and its officers, directors, employees, and agents from and against any claims, liabilities, damages, judgments, awards, losses, costs, or expenses (including reasonable attorneys&apos; fees) arising out of or relating to your violation of these Terms or your use of the Service, including any scanning of websites without proper authorization.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">11. Termination</h2>
            <p className="mt-3">
              We may terminate or suspend your account and access to the Service immediately, without prior notice, for any reason, including breach of these Terms. Upon termination, your right to use the Service will immediately cease.
            </p>
            <p className="mt-3">
              You may terminate your account at any time by contacting us at <a href="mailto:stefan@scanmysaas.com" className="text-emerald-400 hover:underline">stefan@scanmysaas.com</a>. All provisions of these Terms which by their nature should survive termination shall survive, including ownership, warranty disclaimers, indemnity, and limitations of liability.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">12. Governing Law</h2>
            <p className="mt-3">
              These Terms shall be governed by and construed in accordance with the laws of the State of Delaware, United States, without regard to its conflict of law provisions. Any disputes arising under these Terms shall be subject to the exclusive jurisdiction of the courts located in Delaware.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">13. Changes to Terms</h2>
            <p className="mt-3">
              We reserve the right to modify or replace these Terms at any time. If a revision is material, we will provide at least 30 days&apos; notice prior to any new terms taking effect. Your continued use of the Service after changes constitutes acceptance of the new Terms.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">14. Severability</h2>
            <p className="mt-3">
              If any provision of these Terms is held to be unenforceable or invalid, such provision will be modified to the minimum extent necessary to make it enforceable, and the remaining provisions will continue in full force and effect.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">15. Contact Us</h2>
            <p className="mt-3">If you have any questions about these Terms, please contact us:</p>
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
