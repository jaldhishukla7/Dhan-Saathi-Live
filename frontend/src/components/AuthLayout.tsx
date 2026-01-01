import React from "react";

type AuthLayoutProps = {
  title: string;
  subtitle: string;
  children: React.ReactNode;
  imageSide?: "left" | "right";
};

const AuthLayout = ({
  title,
  subtitle,
  children,
  imageSide = "left",
}: AuthLayoutProps) => {
  const financeImage =
    "https://images.unsplash.com/photo-1551288049-bebda4e38f71?q=80&w=1600";

  const isImageRight = imageSide === "right";

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="w-full max-w-6xl grid grid-cols-1 lg:grid-cols-2 bg-white rounded-3xl shadow-xl overflow-hidden">
        
        {/* IMAGE / VISUAL SIDE */}
        <div
          className={`relative hidden lg:flex flex-col justify-between ${
            isImageRight ? "order-2" : ""
          }`}
        >
          <img
            src={financeImage}
            alt="Finance analytics"
            className="absolute inset-0 h-full w-full object-cover"
          />
          <div className="absolute inset-0 bg-gradient-to-br from-emerald-900/85 to-slate-900/90" />

          <div className="relative z-10 p-12 h-full flex flex-col justify-between text-white">
            {/* Branding */}
            <div>
              <h1 className="text-4xl font-bold">Dhan Saathi</h1>
              <p className="mt-2 text-emerald-200">
                Smart finance. Smarter future.
              </p>
            </div>

            {/* Animated Stats */}
            <div className="space-y-6">
              <h2 className="text-3xl font-semibold leading-snug">
                Your money, <br /> growing every day
              </h2>

              <div className="grid grid-cols-3 gap-4">
                <StatCard label="Total Savings" value="₹4.8L" />
                <StatCard label="Monthly Growth" value="+12.4%" />
                <StatCard label="Active Users" value="32K+" />
              </div>

              {/* Mini Chart */}
              <div className="mt-6">
                <p className="text-sm mb-3 text-emerald-200">
                  Portfolio performance
                </p>
                <div className="flex items-end gap-2 h-24">
                  {[40, 60, 50, 80, 65, 95].map((h, i) => (
                    <div
                      key={i}
                      style={{ height: `${h}%` }}
                      className="w-6 rounded-md bg-emerald-400/80 animate-bar"
                    />
                  ))}
                </div>
              </div>
            </div>

            <p className="text-xs text-white/60">
              Real-time insights • Bank-grade security
            </p>
          </div>
        </div>

        {/* FORM SIDE */}
        <div className="flex items-center justify-center p-8 lg:p-14">
          <div className="w-full max-w-md">
            <h2 className="text-3xl font-bold text-slate-900">{title}</h2>
            <p className="text-slate-600 mt-2 mb-8">{subtitle}</p>
            {children}
          </div>
        </div>
      </div>

      {/* Animations */}
      <style>
        {`
          .animate-bar {
            animation: grow 2.5s ease-in-out infinite alternate;
          }
          @keyframes grow {
            from { opacity: 0.6; }
            to { opacity: 1; }
          }
        `}
      </style>
    </div>
  );
};

export default AuthLayout;

/* ---------- Helper ---------- */
const StatCard = ({ label, value }: { label: string; value: string }) => (
  <div className="rounded-xl bg-white/10 backdrop-blur-md border border-white/20 p-4 text-center animate-pulse">
    <p className="text-xs uppercase tracking-wide text-white/70">
      {label}
    </p>
    <p className="text-xl font-bold mt-1">{value}</p>
  </div>
);
