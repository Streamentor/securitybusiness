"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useSession } from "next-auth/react";
import Link from "next/link";
import { motion } from "framer-motion";
import {
  Shield,
  Users,
  ScanLine,
  DollarSign,
  TrendingUp,
  Search,
  ExternalLink,
  ArrowLeft,
  Crown,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  CreditCard,
  BarChart3,
  Eye,
  ChevronDown,
  Loader2,
  RefreshCw,
  UserCheck,
  Zap,
} from "lucide-react";

// ── Types ──

interface Overview {
  totalUsers: number;
  usersLast30d: number;
  usersLast7d: number;
  totalScans: number;
  scansLast30d: number;
  scansLast7d: number;
  payingUsers: number;
  estimatedMRR: number;
  conversionRate: string;
}

interface AdminUser {
  id: string;
  name: string;
  email: string;
  role: string;
  plan: string;
  credits: number;
  scansUsed: number;
  stripeCustomerId: string | null;
  stripeSubscriptionId: string | null;
  stripePriceId: string | null;
  currentPeriodEnd: string | null;
  createdAt: string;
  updatedAt: string;
  image: string | null;
  _count: { scans: number };
}

interface AdminScan {
  id: string;
  url: string;
  status: string;
  overallScore: number | null;
  totalPages: number;
  pagesScanned: number;
  createdAt: string;
  completedAt: string | null;
  userId: string | null;
  user: { name: string; email: string } | null;
  _count: { vulnerabilities: number };
}

interface UserDetail extends AdminUser {
  scans: {
    id: string;
    url: string;
    status: string;
    overallScore: number | null;
    pagesScanned: number;
    createdAt: string;
    completedAt: string | null;
    _count: { vulnerabilities: number };
  }[];
}

interface StatsData {
  overview: Overview;
  plans: Record<string, number>;
  vulnBySeverity: Record<string, number>;
  recentUsers: AdminUser[];
  recentScans: AdminScan[];
}

// ── Helpers ──

function formatDate(date: string) {
  return new Date(date).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function shortDate(date: string) {
  return new Date(date).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

function timeAgo(date: string) {
  const seconds = Math.floor(
    (new Date().getTime() - new Date(date).getTime()) / 1000
  );
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;
  return shortDate(date);
}

function planBadge(plan: string) {
  switch (plan) {
    case "pro":
      return "bg-purple-500/10 text-purple-400 border-purple-500/20";
    case "starter":
      return "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
    default:
      return "bg-gray-500/10 text-gray-400 border-gray-500/20";
  }
}

function scoreBadge(score: number | null) {
  if (score === null) return "text-gray-500";
  if (score >= 80) return "text-emerald-400";
  if (score >= 60) return "text-yellow-400";
  if (score >= 40) return "text-orange-400";
  return "text-red-400";
}

function statusIcon(status: string) {
  switch (status) {
    case "completed":
      return <CheckCircle2 className="h-4 w-4 text-emerald-400" />;
    case "running":
      return <Loader2 className="h-4 w-4 animate-spin text-cyan-400" />;
    case "failed":
      return <XCircle className="h-4 w-4 text-red-400" />;
    default:
      return <Clock className="h-4 w-4 text-gray-400" />;
  }
}

// ── Main Page ──

export default function AdminDashboard() {
  const { data: session, status: sessionStatus } = useSession();
  const router = useRouter();

  const [stats, setStats] = useState<StatsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Users tab state
  const [activeTab, setActiveTab] = useState<
    "overview" | "users" | "scans" | "user-detail"
  >("overview");
  const [allUsers, setAllUsers] = useState<AdminUser[]>([]);
  const [usersTotal, setUsersTotal] = useState(0);
  const [usersPage, setUsersPage] = useState(1);
  const [usersTotalPages, setUsersTotalPages] = useState(1);
  const [usersSearch, setUsersSearch] = useState("");
  const [usersPlanFilter, setUsersPlanFilter] = useState("all");
  const [usersLoading, setUsersLoading] = useState(false);

  // User detail state
  const [selectedUser, setSelectedUser] = useState<UserDetail | null>(null);
  const [userDetailLoading, setUserDetailLoading] = useState(false);

  // Redirect non-authenticated
  useEffect(() => {
    if (sessionStatus === "unauthenticated") {
      router.push("/login?redirect=/admin");
    }
  }, [sessionStatus, router]);

  // Fetch stats
  const fetchStats = useCallback(async () => {
    try {
      setLoading(true);
      const res = await fetch("/api/admin/stats");
      if (res.status === 403) {
        setError("Access denied. Admin only.");
        return;
      }
      if (!res.ok) throw new Error("Failed to fetch");
      const data = await res.json();
      setStats(data);
    } catch {
      setError("Failed to load admin data.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (sessionStatus === "authenticated") {
      fetchStats();
    }
  }, [sessionStatus, fetchStats]);

  // Fetch users list
  const fetchUsers = useCallback(
    async (page = 1) => {
      try {
        setUsersLoading(true);
        const params = new URLSearchParams();
        params.set("page", String(page));
        if (usersSearch) params.set("search", usersSearch);
        if (usersPlanFilter !== "all") params.set("plan", usersPlanFilter);

        const res = await fetch(`/api/admin/users?${params}`);
        if (!res.ok) throw new Error("Failed");
        const data = await res.json();
        setAllUsers(data.users);
        setUsersTotal(data.total);
        setUsersPage(data.page);
        setUsersTotalPages(data.totalPages);
      } catch {
        // silent
      } finally {
        setUsersLoading(false);
      }
    },
    [usersSearch, usersPlanFilter]
  );

  useEffect(() => {
    if (activeTab === "users") {
      fetchUsers(1);
    }
  }, [activeTab, fetchUsers]);

  // Fetch user detail
  async function openUserDetail(userId: string) {
    setUserDetailLoading(true);
    setActiveTab("user-detail");
    try {
      const res = await fetch(`/api/admin/users/${userId}`);
      if (!res.ok) throw new Error("Failed");
      const data = await res.json();
      setSelectedUser(data);
    } catch {
      setSelectedUser(null);
    } finally {
      setUserDetailLoading(false);
    }
  }

  // ── Loading / Error states ──

  if (sessionStatus === "loading" || loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-950">
        <Loader2 className="h-8 w-8 animate-spin text-emerald-400" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center bg-gray-950 gap-4">
        <Shield className="h-16 w-16 text-red-400" />
        <h1 className="text-2xl font-bold text-white">{error}</h1>
        <Link
          href="/dashboard"
          className="text-emerald-400 hover:text-emerald-300 underline"
        >
          ← Back to Dashboard
        </Link>
      </div>
    );
  }

  if (!stats) return null;

  const { overview } = stats;

  // ── Render ──

  return (
    <div className="min-h-screen bg-gray-950">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b border-gray-800 bg-gray-950/80 backdrop-blur-xl">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-4 sm:px-6">
          <div className="flex items-center gap-3">
            <Link href="/dashboard" className="text-gray-400 hover:text-white transition-colors">
              <ArrowLeft className="h-5 w-5" />
            </Link>
            <div className="flex items-center gap-2">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-emerald-500 to-cyan-500">
                <Crown className="h-5 w-5 text-white" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-white">Admin Dashboard</h1>
                <p className="text-xs text-gray-500">
                  {session?.user?.name} • {session?.user?.email}
                </p>
              </div>
            </div>
          </div>
          <button
            onClick={() => fetchStats()}
            className="flex items-center gap-2 rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-gray-300 hover:bg-gray-800 transition-colors"
          >
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
        </div>
      </header>

      <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6">
        {/* Tabs */}
        <div className="mb-6 flex gap-1 rounded-xl border border-gray-800 bg-gray-900/50 p-1">
          {(
            [
              { key: "overview", label: "Overview", icon: BarChart3 },
              { key: "users", label: "Users", icon: Users },
              { key: "scans", label: "Recent Scans", icon: ScanLine },
            ] as const
          ).map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              className={`flex flex-1 items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-sm font-medium transition-all ${
                activeTab === key || (activeTab === "user-detail" && key === "users")
                  ? "bg-gray-800 text-white shadow-sm"
                  : "text-gray-400 hover:text-gray-300"
              }`}
            >
              <Icon className="h-4 w-4" />
              {label}
            </button>
          ))}
        </div>

        {/* ── Overview Tab ── */}
        {activeTab === "overview" && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-6"
          >
            {/* KPI Cards */}
            <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
              {[
                {
                  label: "Total Users",
                  value: overview.totalUsers,
                  sub: `+${overview.usersLast7d} this week`,
                  icon: Users,
                  color: "from-blue-500 to-cyan-500",
                },
                {
                  label: "Total Scans",
                  value: overview.totalScans,
                  sub: `+${overview.scansLast7d} this week`,
                  icon: ScanLine,
                  color: "from-emerald-500 to-green-500",
                },
                {
                  label: "Paying Users",
                  value: overview.payingUsers,
                  sub: `${overview.conversionRate}% conversion`,
                  icon: CreditCard,
                  color: "from-purple-500 to-pink-500",
                },
                {
                  label: "Est. MRR",
                  value: `$${overview.estimatedMRR}`,
                  sub: `${overview.payingUsers} subscriptions`,
                  icon: DollarSign,
                  color: "from-amber-500 to-orange-500",
                },
              ].map((card, i) => (
                <motion.div
                  key={card.label}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.05 }}
                  className="rounded-xl border border-gray-800 bg-gray-900 p-5"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-400">{card.label}</span>
                    <div
                      className={`flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br ${card.color}`}
                    >
                      <card.icon className="h-4 w-4 text-white" />
                    </div>
                  </div>
                  <p className="mt-2 text-3xl font-bold text-white">
                    {card.value}
                  </p>
                  <p className="mt-1 flex items-center gap-1 text-xs text-gray-500">
                    <TrendingUp className="h-3 w-3 text-emerald-400" />
                    {card.sub}
                  </p>
                </motion.div>
              ))}
            </div>

            {/* Growth + Plans Row */}
            <div className="grid gap-4 lg:grid-cols-2">
              {/* Growth Stats */}
              <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
                <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
                  <TrendingUp className="h-4 w-4 text-emerald-400" />
                  Growth
                </h3>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-400">
                      Users (last 30d)
                    </span>
                    <span className="text-lg font-semibold text-white">
                      +{overview.usersLast30d}
                    </span>
                  </div>
                  <div className="h-px bg-gray-800" />
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-400">
                      Users (last 7d)
                    </span>
                    <span className="text-lg font-semibold text-white">
                      +{overview.usersLast7d}
                    </span>
                  </div>
                  <div className="h-px bg-gray-800" />
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-400">
                      Scans (last 30d)
                    </span>
                    <span className="text-lg font-semibold text-white">
                      +{overview.scansLast30d}
                    </span>
                  </div>
                  <div className="h-px bg-gray-800" />
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-400">
                      Scans (last 7d)
                    </span>
                    <span className="text-lg font-semibold text-white">
                      +{overview.scansLast7d}
                    </span>
                  </div>
                </div>
              </div>

              {/* Plan Distribution */}
              <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
                <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
                  <Zap className="h-4 w-4 text-purple-400" />
                  Plan Distribution
                </h3>
                <div className="space-y-3">
                  {["free", "starter", "pro"].map((plan) => {
                    const count = stats.plans[plan] || 0;
                    const pct =
                      overview.totalUsers > 0
                        ? (count / overview.totalUsers) * 100
                        : 0;
                    return (
                      <div key={plan}>
                        <div className="mb-1 flex items-center justify-between text-sm">
                          <span className="capitalize text-gray-300">
                            {plan}
                          </span>
                          <span className="text-gray-400">
                            {count} ({pct.toFixed(0)}%)
                          </span>
                        </div>
                        <div className="h-2 rounded-full bg-gray-800">
                          <div
                            className={`h-2 rounded-full transition-all ${
                              plan === "pro"
                                ? "bg-purple-500"
                                : plan === "starter"
                                ? "bg-emerald-500"
                                : "bg-gray-600"
                            }`}
                            style={{ width: `${Math.max(pct, 2)}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>

                <div className="mt-5 h-px bg-gray-800" />

                <h4 className="mt-4 text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-orange-400" />
                  Vulnerabilities Found
                </h4>
                <div className="grid grid-cols-5 gap-2">
                  {["critical", "high", "medium", "low", "info"].map((sev) => (
                    <div
                      key={sev}
                      className="rounded-lg border border-gray-800 bg-gray-800/50 p-2 text-center"
                    >
                      <p
                        className={`text-lg font-bold ${
                          sev === "critical"
                            ? "text-red-400"
                            : sev === "high"
                            ? "text-orange-400"
                            : sev === "medium"
                            ? "text-yellow-400"
                            : sev === "low"
                            ? "text-blue-400"
                            : "text-gray-400"
                        }`}
                      >
                        {stats.vulnBySeverity[sev] || 0}
                      </p>
                      <p className="mt-0.5 text-[10px] capitalize text-gray-500">
                        {sev}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Recent Users */}
            <div className="rounded-xl border border-gray-800 bg-gray-900">
              <div className="flex items-center justify-between border-b border-gray-800 px-5 py-4">
                <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
                  <UserCheck className="h-4 w-4 text-blue-400" />
                  Recent Signups
                </h3>
                <button
                  onClick={() => setActiveTab("users")}
                  className="text-xs text-emerald-400 hover:text-emerald-300"
                >
                  View all →
                </button>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-800 text-left text-xs text-gray-500">
                      <th className="px-5 py-3 font-medium">User</th>
                      <th className="px-5 py-3 font-medium">Plan</th>
                      <th className="px-5 py-3 font-medium">Credits</th>
                      <th className="px-5 py-3 font-medium">Scans</th>
                      <th className="px-5 py-3 font-medium">Joined</th>
                      <th className="px-5 py-3 font-medium"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {stats.recentUsers.map((u) => (
                      <tr
                        key={u.id}
                        className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors"
                      >
                        <td className="px-5 py-3">
                          <div>
                            <p className="font-medium text-white">{u.name}</p>
                            <p className="text-xs text-gray-500">{u.email}</p>
                          </div>
                        </td>
                        <td className="px-5 py-3">
                          <span
                            className={`inline-flex rounded-full border px-2 py-0.5 text-xs font-medium capitalize ${planBadge(
                              u.plan
                            )}`}
                          >
                            {u.plan}
                          </span>
                        </td>
                        <td className="px-5 py-3 text-gray-300">
                          {u.credits}
                        </td>
                        <td className="px-5 py-3 text-gray-300">
                          {u._count.scans}
                        </td>
                        <td className="px-5 py-3 text-gray-400">
                          {timeAgo(u.createdAt)}
                        </td>
                        <td className="px-5 py-3">
                          <button
                            onClick={() => openUserDetail(u.id)}
                            className="text-gray-500 hover:text-emerald-400 transition-colors"
                          >
                            <Eye className="h-4 w-4" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Recent Scans */}
            <div className="rounded-xl border border-gray-800 bg-gray-900">
              <div className="flex items-center justify-between border-b border-gray-800 px-5 py-4">
                <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
                  <ScanLine className="h-4 w-4 text-emerald-400" />
                  Recent Scans
                </h3>
                <button
                  onClick={() => setActiveTab("scans")}
                  className="text-xs text-emerald-400 hover:text-emerald-300"
                >
                  View all →
                </button>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-800 text-left text-xs text-gray-500">
                      <th className="px-5 py-3 font-medium">URL</th>
                      <th className="px-5 py-3 font-medium">User</th>
                      <th className="px-5 py-3 font-medium">Status</th>
                      <th className="px-5 py-3 font-medium">Score</th>
                      <th className="px-5 py-3 font-medium">Vulns</th>
                      <th className="px-5 py-3 font-medium">When</th>
                    </tr>
                  </thead>
                  <tbody>
                    {stats.recentScans.slice(0, 10).map((s) => (
                      <tr
                        key={s.id}
                        className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors"
                      >
                        <td className="max-w-[200px] truncate px-5 py-3">
                          <Link
                            href={`/scan/${s.id}`}
                            className="text-cyan-400 hover:text-cyan-300 hover:underline"
                          >
                            {s.url.replace(/^https?:\/\//, "")}
                          </Link>
                        </td>
                        <td className="px-5 py-3 text-gray-400">
                          {s.user?.name || (
                            <span className="text-gray-600">anonymous</span>
                          )}
                        </td>
                        <td className="px-5 py-3">
                          <div className="flex items-center gap-1.5">
                            {statusIcon(s.status)}
                            <span className="capitalize text-gray-300">
                              {s.status}
                            </span>
                          </div>
                        </td>
                        <td
                          className={`px-5 py-3 font-semibold ${scoreBadge(
                            s.overallScore
                          )}`}
                        >
                          {s.overallScore ?? "—"}
                        </td>
                        <td className="px-5 py-3 text-gray-300">
                          {s._count.vulnerabilities}
                        </td>
                        <td className="px-5 py-3 text-gray-400">
                          {timeAgo(s.createdAt)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </motion.div>
        )}

        {/* ── Users Tab ── */}
        {activeTab === "users" && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-4"
          >
            {/* Filters */}
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
                <input
                  type="text"
                  placeholder="Search by name or email..."
                  value={usersSearch}
                  onChange={(e) => setUsersSearch(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && fetchUsers(1)}
                  className="w-full rounded-lg border border-gray-700 bg-gray-900 py-2.5 pl-10 pr-4 text-sm text-white placeholder-gray-500 focus:border-emerald-500 focus:outline-none"
                />
              </div>
              <div className="relative">
                <select
                  value={usersPlanFilter}
                  onChange={(e) => setUsersPlanFilter(e.target.value)}
                  className="appearance-none rounded-lg border border-gray-700 bg-gray-900 py-2.5 pl-4 pr-10 text-sm text-white focus:border-emerald-500 focus:outline-none"
                >
                  <option value="all">All Plans</option>
                  <option value="free">Free</option>
                  <option value="starter">Starter</option>
                  <option value="pro">Pro</option>
                </select>
                <ChevronDown className="absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500 pointer-events-none" />
              </div>
              <button
                onClick={() => fetchUsers(1)}
                className="rounded-lg bg-emerald-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-emerald-500 transition-colors"
              >
                Search
              </button>
            </div>

            {/* Count */}
            <p className="text-sm text-gray-500">
              {usersTotal} user{usersTotal !== 1 ? "s" : ""} found
            </p>

            {/* Users Table */}
            <div className="rounded-xl border border-gray-800 bg-gray-900 overflow-x-auto">
              {usersLoading ? (
                <div className="flex items-center justify-center py-16">
                  <Loader2 className="h-6 w-6 animate-spin text-emerald-400" />
                </div>
              ) : (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-800 text-left text-xs text-gray-500">
                      <th className="px-5 py-3 font-medium">User</th>
                      <th className="px-5 py-3 font-medium">Plan</th>
                      <th className="px-5 py-3 font-medium">Credits</th>
                      <th className="px-5 py-3 font-medium">Scans Used</th>
                      <th className="px-5 py-3 font-medium">Total Scans</th>
                      <th className="px-5 py-3 font-medium">Stripe</th>
                      <th className="px-5 py-3 font-medium">Joined</th>
                      <th className="px-5 py-3 font-medium"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {allUsers.map((u) => (
                      <tr
                        key={u.id}
                        className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors"
                      >
                        <td className="px-5 py-3">
                          <div className="flex items-center gap-2">
                            {u.role === "admin" && (
                              <Crown className="h-3.5 w-3.5 text-amber-400" />
                            )}
                            <div>
                              <p className="font-medium text-white">
                                {u.name}
                              </p>
                              <p className="text-xs text-gray-500">
                                {u.email}
                              </p>
                            </div>
                          </div>
                        </td>
                        <td className="px-5 py-3">
                          <span
                            className={`inline-flex rounded-full border px-2 py-0.5 text-xs font-medium capitalize ${planBadge(
                              u.plan
                            )}`}
                          >
                            {u.plan}
                          </span>
                        </td>
                        <td className="px-5 py-3 text-gray-300">
                          {u.credits}
                        </td>
                        <td className="px-5 py-3 text-gray-300">
                          {u.scansUsed}
                        </td>
                        <td className="px-5 py-3 text-gray-300">
                          {u._count.scans}
                        </td>
                        <td className="px-5 py-3">
                          {u.stripeCustomerId ? (
                            <span className="inline-flex items-center gap-1 text-xs text-emerald-400">
                              <CreditCard className="h-3 w-3" />
                              Active
                            </span>
                          ) : (
                            <span className="text-xs text-gray-600">—</span>
                          )}
                        </td>
                        <td className="px-5 py-3 text-gray-400 whitespace-nowrap">
                          {shortDate(u.createdAt)}
                        </td>
                        <td className="px-5 py-3">
                          <button
                            onClick={() => openUserDetail(u.id)}
                            className="text-gray-500 hover:text-emerald-400 transition-colors"
                          >
                            <Eye className="h-4 w-4" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>

            {/* Pagination */}
            {usersTotalPages > 1 && (
              <div className="flex items-center justify-center gap-2">
                <button
                  onClick={() => fetchUsers(usersPage - 1)}
                  disabled={usersPage <= 1}
                  className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-gray-300 hover:bg-gray-800 disabled:opacity-40"
                >
                  Previous
                </button>
                <span className="text-sm text-gray-400">
                  Page {usersPage} of {usersTotalPages}
                </span>
                <button
                  onClick={() => fetchUsers(usersPage + 1)}
                  disabled={usersPage >= usersTotalPages}
                  className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-gray-300 hover:bg-gray-800 disabled:opacity-40"
                >
                  Next
                </button>
              </div>
            )}
          </motion.div>
        )}

        {/* ── Scans Tab ── */}
        {activeTab === "scans" && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <div className="rounded-xl border border-gray-800 bg-gray-900 overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-800 text-left text-xs text-gray-500">
                    <th className="px-5 py-3 font-medium">URL</th>
                    <th className="px-5 py-3 font-medium">User</th>
                    <th className="px-5 py-3 font-medium">Status</th>
                    <th className="px-5 py-3 font-medium">Score</th>
                    <th className="px-5 py-3 font-medium">Pages</th>
                    <th className="px-5 py-3 font-medium">Vulns</th>
                    <th className="px-5 py-3 font-medium">Started</th>
                    <th className="px-5 py-3 font-medium">Completed</th>
                    <th className="px-5 py-3 font-medium"></th>
                  </tr>
                </thead>
                <tbody>
                  {stats.recentScans.map((s) => (
                    <tr
                      key={s.id}
                      className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors"
                    >
                      <td className="max-w-[220px] truncate px-5 py-3 text-white">
                        {s.url.replace(/^https?:\/\//, "")}
                      </td>
                      <td className="px-5 py-3">
                        {s.user ? (
                          <button
                            onClick={() =>
                              s.userId && openUserDetail(s.userId)
                            }
                            className="text-cyan-400 hover:underline text-left"
                          >
                            {s.user.name}
                          </button>
                        ) : (
                          <span className="text-gray-600">anonymous</span>
                        )}
                      </td>
                      <td className="px-5 py-3">
                        <div className="flex items-center gap-1.5">
                          {statusIcon(s.status)}
                          <span className="capitalize text-gray-300">
                            {s.status}
                          </span>
                        </div>
                      </td>
                      <td
                        className={`px-5 py-3 font-semibold ${scoreBadge(
                          s.overallScore
                        )}`}
                      >
                        {s.overallScore ?? "—"}
                      </td>
                      <td className="px-5 py-3 text-gray-300">
                        {s.pagesScanned}
                      </td>
                      <td className="px-5 py-3 text-gray-300">
                        {s._count.vulnerabilities}
                      </td>
                      <td className="px-5 py-3 text-gray-400 whitespace-nowrap">
                        {formatDate(s.createdAt)}
                      </td>
                      <td className="px-5 py-3 text-gray-400 whitespace-nowrap">
                        {s.completedAt ? formatDate(s.completedAt) : "—"}
                      </td>
                      <td className="px-5 py-3">
                        <Link
                          href={`/scan/${s.id}`}
                          className="text-gray-500 hover:text-emerald-400 transition-colors"
                        >
                          <ExternalLink className="h-4 w-4" />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </motion.div>
        )}

        {/* ── User Detail Tab ── */}
        {activeTab === "user-detail" && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-6"
          >
            <button
              onClick={() => setActiveTab("users")}
              className="flex items-center gap-2 text-sm text-gray-400 hover:text-white transition-colors"
            >
              <ArrowLeft className="h-4 w-4" />
              Back to Users
            </button>

            {userDetailLoading ? (
              <div className="flex items-center justify-center py-20">
                <Loader2 className="h-6 w-6 animate-spin text-emerald-400" />
              </div>
            ) : selectedUser ? (
              <>
                {/* User Profile Card */}
                <div className="rounded-xl border border-gray-800 bg-gray-900 p-6">
                  <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                    <div className="flex items-center gap-4">
                      {selectedUser.image ? (
                        <img
                          src={selectedUser.image}
                          alt={selectedUser.name}
                          className="h-14 w-14 rounded-full border-2 border-gray-700"
                        />
                      ) : (
                        <div className="flex h-14 w-14 items-center justify-center rounded-full bg-gray-800 text-xl font-bold text-gray-400">
                          {selectedUser.name.charAt(0).toUpperCase()}
                        </div>
                      )}
                      <div>
                        <div className="flex items-center gap-2">
                          <h2 className="text-xl font-bold text-white">
                            {selectedUser.name}
                          </h2>
                          {selectedUser.role === "admin" && (
                            <Crown className="h-4 w-4 text-amber-400" />
                          )}
                        </div>
                        <p className="text-sm text-gray-400">
                          {selectedUser.email}
                        </p>
                        <p className="mt-1 text-xs text-gray-500">
                          ID: {selectedUser.id}
                        </p>
                      </div>
                    </div>
                    <span
                      className={`self-start inline-flex rounded-full border px-3 py-1 text-sm font-medium capitalize ${planBadge(
                        selectedUser.plan
                      )}`}
                    >
                      {selectedUser.plan}
                    </span>
                  </div>
                </div>

                {/* Stats Grid */}
                <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
                  {[
                    {
                      label: "Credits Left",
                      value: selectedUser.credits,
                      icon: Zap,
                    },
                    {
                      label: "Scans Used",
                      value: selectedUser.scansUsed,
                      icon: ScanLine,
                    },
                    {
                      label: "Total Scans",
                      value: selectedUser.scans.length,
                      icon: BarChart3,
                    },
                    {
                      label: "Joined",
                      value: shortDate(selectedUser.createdAt),
                      icon: Clock,
                    },
                  ].map((s) => (
                    <div
                      key={s.label}
                      className="rounded-xl border border-gray-800 bg-gray-900 p-4"
                    >
                      <div className="flex items-center gap-2 text-gray-400 mb-1">
                        <s.icon className="h-4 w-4" />
                        <span className="text-xs">{s.label}</span>
                      </div>
                      <p className="text-xl font-bold text-white">{s.value}</p>
                    </div>
                  ))}
                </div>

                {/* Stripe Info */}
                <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
                  <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
                    <CreditCard className="h-4 w-4 text-purple-400" />
                    Subscription Details
                  </h3>
                  <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 text-sm">
                    <div>
                      <span className="text-gray-500">Customer ID</span>
                      <p className="text-gray-300 font-mono text-xs mt-1">
                        {selectedUser.stripeCustomerId || "—"}
                      </p>
                    </div>
                    <div>
                      <span className="text-gray-500">Subscription ID</span>
                      <p className="text-gray-300 font-mono text-xs mt-1">
                        {selectedUser.stripeSubscriptionId || "—"}
                      </p>
                    </div>
                    <div>
                      <span className="text-gray-500">Price ID</span>
                      <p className="text-gray-300 font-mono text-xs mt-1">
                        {selectedUser.stripePriceId || "—"}
                      </p>
                    </div>
                    <div>
                      <span className="text-gray-500">Current Period End</span>
                      <p className="text-gray-300 mt-1">
                        {selectedUser.currentPeriodEnd
                          ? formatDate(selectedUser.currentPeriodEnd)
                          : "—"}
                      </p>
                    </div>
                  </div>
                </div>

                {/* User's Scans */}
                <div className="rounded-xl border border-gray-800 bg-gray-900">
                  <div className="border-b border-gray-800 px-5 py-4">
                    <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
                      <ScanLine className="h-4 w-4 text-emerald-400" />
                      Scan History ({selectedUser.scans.length})
                    </h3>
                  </div>
                  {selectedUser.scans.length === 0 ? (
                    <p className="px-5 py-8 text-center text-sm text-gray-500">
                      No scans yet
                    </p>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-sm">
                        <thead>
                          <tr className="border-b border-gray-800 text-left text-xs text-gray-500">
                            <th className="px-5 py-3 font-medium">URL</th>
                            <th className="px-5 py-3 font-medium">Status</th>
                            <th className="px-5 py-3 font-medium">Score</th>
                            <th className="px-5 py-3 font-medium">Pages</th>
                            <th className="px-5 py-3 font-medium">Vulns</th>
                            <th className="px-5 py-3 font-medium">Date</th>
                            <th className="px-5 py-3 font-medium"></th>
                          </tr>
                        </thead>
                        <tbody>
                          {selectedUser.scans.map((sc) => (
                            <tr
                              key={sc.id}
                              className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors"
                            >
                              <td className="max-w-[200px] truncate px-5 py-3 text-white">
                                {sc.url.replace(/^https?:\/\//, "")}
                              </td>
                              <td className="px-5 py-3">
                                <div className="flex items-center gap-1.5">
                                  {statusIcon(sc.status)}
                                  <span className="capitalize text-gray-300">
                                    {sc.status}
                                  </span>
                                </div>
                              </td>
                              <td
                                className={`px-5 py-3 font-semibold ${scoreBadge(
                                  sc.overallScore
                                )}`}
                              >
                                {sc.overallScore ?? "—"}
                              </td>
                              <td className="px-5 py-3 text-gray-300">
                                {sc.pagesScanned}
                              </td>
                              <td className="px-5 py-3 text-gray-300">
                                {sc._count.vulnerabilities}
                              </td>
                              <td className="px-5 py-3 text-gray-400 whitespace-nowrap">
                                {formatDate(sc.createdAt)}
                              </td>
                              <td className="px-5 py-3">
                                <Link
                                  href={`/scan/${sc.id}`}
                                  className="text-gray-500 hover:text-emerald-400 transition-colors"
                                >
                                  <ExternalLink className="h-4 w-4" />
                                </Link>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </>
            ) : (
              <p className="text-center text-gray-500 py-10">
                User not found.
              </p>
            )}
          </motion.div>
        )}
      </div>
    </div>
  );
}
