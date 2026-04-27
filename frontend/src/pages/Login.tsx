import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  IndianRupee,
  Shield,
  Lock,
  Mail,
  Eye,
  EyeOff,
  ArrowRight,
  AlertCircle,
  CheckCircle,
  XCircle,
  Key,
  TrendingUp,
  BarChart3
} from "lucide-react";
import { loginUser } from "../services/authService";
import logo from '../assets/logo.png';

const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [validationErrors, setValidationErrors] = useState<{ email?: string, password?: string }>({});

  const navigate = useNavigate();

  const validateForm = () => {
    const errors: { email?: string, password?: string } = {};
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!email.trim()) {
      errors.email = "Email is required";
    } else if (!emailRegex.test(email)) {
      errors.email = "Please enter a valid email address";
    }

    if (!password.trim()) {
      errors.password = "Password is required";
    }

    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setValidationErrors({});

    // Validate form
    if (!validateForm()) {
      return;
    }

    setLoading(true);

    try {
      // Your existing loginUser function - keep the exact same
      const data = await loginUser(email, password);

      // Store token - keep the exact same
      localStorage.setItem("access_token", data.access_token);
      localStorage.setItem("user", JSON.stringify(data.user));

      if (remember) {
        localStorage.setItem("remember_me", "true");
      }

      // Show success message
      setError("success");

      // Redirect after a short delay
      setTimeout(() => {
        navigate("/dashboard");
      }, 800);
    } catch (err: any) {
      setError(err.message || "Invalid credentials. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-emerald-50/50 flex items-center justify-center p-4">
      {/* Main Container */}
      <div className="w-full max-w-6xl flex flex-col lg:flex-row bg-white rounded-3xl shadow-2xl overflow-hidden border border-slate-200">

        {/* Left Side - Brand & Features */}
        <div className="lg:w-5/12 bg-gradient-to-br from-emerald-900 to-teal-800 text-white p-10 flex flex-col">
          {/* Logo */}
          <div className="flex items-center gap-3 -ml-8">
            <img
              src={logo}
              alt="DhanSaathi Logo" style={{ height: '135px' }}
              className="h-24 w-auto"
            />
          </div>



          {/* Main Content */}
          <div className="flex-1">
            <h2 className="text-3xl font-bold mb-6 leading-tight">
              Welcome to Your Financial Command Center
            </h2>

            <p className="text-emerald-100 mb-8">
              AI-powered portfolio management, real-time market insights, and intelligent investment strategies.
            </p>

            {/* Features */}
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-white/10 rounded-full flex items-center justify-center">
                  <TrendingUp className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="font-semibold">Real-time Market Data</h4>
                  <p className="text-sm text-emerald-200">Live NSE/BSE indices & stock prices</p>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-white/10 rounded-full flex items-center justify-center">
                  <BarChart3 className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="font-semibold">AI Portfolio Analysis</h4>
                  <p className="text-sm text-emerald-200">87% accurate stock predictions</p>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-white/10 rounded-full flex items-center justify-center">
                  <Shield className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="font-semibold">Bank-grade Security</h4>
                  <p className="text-sm text-emerald-200">256-bit encryption & 2FA protection</p>
                </div>
              </div>
            </div>
          </div>

          {/* Market Stats */}
          <div className="mt-8 pt-6 border-t border-white/20">
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <div className="text-emerald-200">NIFTY 50</div>
                <div className="text-lg font-bold">22,142.35 <span className="text-green-400">+1.2%</span></div>
              </div>
              <div>
                <div className="text-emerald-200">SENSEX</div>
                <div className="text-lg font-bold">73,128.77 <span className="text-green-400">+1.4%</span></div>
              </div>
            </div>
          </div>
        </div>

        {/* Right Side - Login Form */}
        <div className="lg:w-7/12 p-10">
          {/* Header */}
          <div className="text-center mb-10">
            <h2 className="text-3xl font-bold text-slate-900">Welcome Back</h2>
            <p className="text-slate-600 mt-2">Access your financial command center</p>
          </div>

          {/* Success Message */}
          {error === "success" && (
            <div className="mb-6 p-4 bg-gradient-to-r from-emerald-50 to-green-50 border border-emerald-200 rounded-xl">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-emerald-100 rounded-full flex items-center justify-center flex-shrink-0">
                  <CheckCircle className="w-5 h-5 text-emerald-600" />
                </div>
                <div>
                  <h4 className="font-semibold text-emerald-900">Login Successful!</h4>
                  <p className="text-sm text-emerald-700">Redirecting to your dashboard...</p>
                </div>
              </div>
            </div>
          )}

          {/* Error Message */}
          {error && error !== "success" && (
            <div className="mb-6 p-4 bg-gradient-to-r from-red-50 to-rose-50 border border-red-200 rounded-xl">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-red-100 rounded-full flex items-center justify-center flex-shrink-0">
                  <AlertCircle className="w-5 h-5 text-red-600" />
                </div>
                <div>
                  <h4 className="font-semibold text-red-900">Authentication Failed</h4>
                  <p className="text-sm text-red-700">{error}</p>
                </div>
              </div>
            </div>
          )}

          {/* Form Card */}
          <div className="bg-white rounded-2xl border border-slate-200 shadow-lg p-8">
            <form onSubmit={handleLogin} className="space-y-6">
              {/* Email Field */}
              <div>
                <label className="block text-sm font-semibold text-slate-800 mb-2">
                  Email Address
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                    <Mail className={`w-5 h-5 ${validationErrors.email ? 'text-red-400' : 'text-slate-400'}`} />
                  </div>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => {
                      setEmail(e.target.value);
                      if (validationErrors.email) {
                        setValidationErrors(prev => ({ ...prev, email: undefined }));
                      }
                    }}
                    className={`w-full pl-12 pr-4 py-3.5 border-2 rounded-xl focus:ring-2 focus:ring-emerald-500 outline-none transition-all duration-200 ${validationErrors.email
                      ? 'border-red-300 focus:border-red-500'
                      : 'border-slate-200 hover:border-slate-300 focus:border-emerald-500'
                      }`}
                    placeholder="enter@email.com"
                    required
                  />
                  {validationErrors.email && (
                    <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
                      <XCircle className="w-5 h-5 text-red-500" />
                    </div>
                  )}
                </div>
                {validationErrors.email && (
                  <p className="mt-2 text-sm text-red-600 flex items-center gap-1">
                    <AlertCircle className="w-4 h-4" />
                    {validationErrors.email}
                  </p>
                )}
              </div>

              {/* Password Field */}
              <div>
                <label className="block text-sm font-semibold text-slate-800 mb-2">
                  Password
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                    <Lock className={`w-5 h-5 ${validationErrors.password ? 'text-red-400' : 'text-slate-400'}`} />
                  </div>
                  <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => {
                      setPassword(e.target.value);
                      if (validationErrors.password) {
                        setValidationErrors(prev => ({ ...prev, password: undefined }));
                      }
                    }}
                    className={`w-full pl-12 pr-12 py-3.5 border-2 rounded-xl focus:ring-2 focus:ring-emerald-500 outline-none transition-all duration-200 ${validationErrors.password
                      ? 'border-red-300 focus:border-red-500'
                      : 'border-slate-200 hover:border-slate-300 focus:border-emerald-500'
                      }`}
                    placeholder="••••••••"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-slate-400 hover:text-emerald-600 transition-colors"
                  >
                    {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                  {validationErrors.password && (
                    <div className="absolute right-12 top-1/2 transform -translate-y-1/2">
                      <XCircle className="w-5 h-5 text-red-500" />
                    </div>
                  )}
                </div>
                {validationErrors.password && (
                  <p className="mt-2 text-sm text-red-600 flex items-center gap-1">
                    <AlertCircle className="w-4 h-4" />
                    {validationErrors.password}
                  </p>
                )}
              </div>

              {/* Remember & Forgot */}
              <div className="flex items-center justify-between">
                <label className="flex items-center gap-3 cursor-pointer group">
                  <div className={`relative w-5 h-5 border-2 rounded-md transition-all duration-200 ${remember
                    ? 'bg-emerald-500 border-emerald-500'
                    : 'border-slate-300 group-hover:border-emerald-400'
                    }`}>
                    {remember && <CheckCircle className="absolute inset-0 w-full h-full p-0.5 text-white" />}
                  </div>
                  <input
                    type="checkbox"
                    checked={remember}
                    onChange={() => setRemember(!remember)}
                    className="hidden"
                  />
                  <span className="text-sm text-slate-700 select-none">Remember me</span>
                </label>

                <Link
                  to="/forgot-password"
                  className="text-sm font-medium text-emerald-600 hover:text-emerald-700 transition-colors"
                >
                  Forgot password?
                </Link>
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                disabled={loading}
                className="w-full bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-700 hover:to-teal-700 text-white font-semibold py-4 px-6 rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-3 group"
              >
                {loading ? (
                  <>
                    <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                    Signing in...
                  </>
                ) : (
                  <>
                    Sign in to Dashboard
                    <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                  </>
                )}
              </button>

              {/* Sign Up Link */}
              <div className="text-center pt-4">
                <p className="text-slate-600">
                  Don't have an account?{" "}
                  <Link
                    to="/register"
                    className="font-bold text-emerald-600 hover:text-emerald-700 transition-colors"
                  >
                    Create Account
                  </Link>
                </p>
              </div>
            </form>
          </div>

          {/* Security Footer */}
          <div className="mt-8 pt-6 border-t border-slate-100">
            <div className="flex flex-col md:flex-row items-center justify-between gap-4">
              <div className="flex items-center gap-3 text-sm text-slate-500">
                <div className="flex items-center gap-2">
                  <Shield className="w-4 h-4" />
                  <span>256-bit SSL Encryption</span>
                </div>
                <div className="hidden md:block w-1 h-1 bg-slate-300 rounded-full"></div>
                <div className="flex items-center gap-2">
                  <Key className="w-4 h-4" />
                  <span>SEBI Registered</span>
                </div>
              </div>
              <div className="text-xs text-slate-400">
                Your data is protected and never shared
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Market Ticker */}
      <div className="fixed bottom-0 left-0 right-0 bg-slate-900 text-white py-2 px-4">
        <div className="flex overflow-x-auto gap-8 items-center justify-center text-sm">
          <div className="flex items-center gap-2 whitespace-nowrap">
            <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
            <span className="font-medium">NIFTY 50</span>
            <span className="font-bold">22,142.35</span>
            <span className="text-green-400">+1.2%</span>
          </div>
          <div className="flex items-center gap-2 whitespace-nowrap">
            <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
            <span className="font-medium">SENSEX</span>
            <span className="font-bold">73,128.77</span>
            <span className="text-green-400">+1.4%</span>
          </div>
          <div className="flex items-center gap-2 whitespace-nowrap">
            <div className="w-2 h-2 bg-amber-400 rounded-full animate-pulse"></div>
            <span className="font-medium">BANK NIFTY</span>
            <span className="font-bold">46,892.60</span>
            <span className="text-amber-400">+0.8%</span>
          </div>
          <div className="flex items-center gap-2 whitespace-nowrap">
            <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
            <span className="font-medium">NIFTY IT</span>
            <span className="font-bold">37,856.25</span>
            <span className="text-green-400">+2.1%</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;