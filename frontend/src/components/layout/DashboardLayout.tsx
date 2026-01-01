// src/components/layout/DashboardLayout.tsx
import { useState } from 'react';
import { Outlet, Link, useLocation } from 'react-router-dom';
import { 
  Bell, 
  TrendingUp, 
  PieChart, 
  Shield, 
  BarChart3, 
  FileText, 
  Lightbulb,
  Menu,
  X,
  HelpCircle
} from 'lucide-react';

const DashboardLayout = () => {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [user] = useState({
    name: "Jaldhi Shukla",
    avatar: "https://api.dicebear.com/7.x/avataaars/svg?seed=Jaldhi",
    plan: "Premium"
  });

  const navigation = [
    { name: 'AI Insights', href: '/dashboard', icon: Lightbulb },
    { name: 'Portfolio', href: '/portfolio', icon: PieChart },
    { name: 'Stock Predictions', href: '/predictions', icon: TrendingUp },
    { name: 'Market Overview', href: '/market', icon: BarChart3 },
    { name: 'Reports', href: '/reports', icon: FileText },
    { name: 'Security', href: '/security', icon: Shield },
    { name: 'Learn', href: '/learn', icon: HelpCircle },
  ];

  const location = useLocation();

  return (
    <div className="min-h-screen bg-linear-to-br from-slate-50 to-gray-100">
      {/* Mobile sidebar backdrop */}
      {sidebarOpen && (
        <div 
          className="fixed inset-0 z-40 bg-black bg-opacity-50 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside className={`
        fixed inset-y-0 left-0 z-50 w-64 bg-linear-to-b from-emerald-900 to-teal-900 
        text-white transform transition-transform duration-200 ease-in-out
        ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'} lg:translate-x-0
      `}>
        <div className="flex flex-col h-full">
          {/* Logo */}
          <div className="p-6 border-b border-emerald-800/50">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 bg-linear-to-br from-emerald-400 to-teal-500 rounded-xl flex items-center justify-center">
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <div>
                <h1 className="text-xl font-bold">DhanSaathi</h1>
                <p className="text-emerald-200 text-xs">AI Financial Assistant</p>
              </div>
            </div>
          </div>

          {/* Navigation */}
          <nav className="flex-1 p-4 space-y-2">
            {navigation.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.href;
              
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`
                    flex items-center space-x-3 px-4 py-3 rounded-xl transition-all duration-200
                    ${isActive 
                      ? 'bg-emerald-800/50 text-white shadow-lg' 
                      : 'text-emerald-100 hover:bg-emerald-800/30 hover:scale-[1.02]'
                    }
                  `}
                >
                  <Icon className="w-5 h-5" />
                  <span className="font-medium">{item.name}</span>
                </Link>
              );
            })}
          </nav>

          {/* User Profile */}
          <div className="p-4 border-t border-emerald-800/50">
            <div className="flex items-center space-x-3 p-3 rounded-lg bg-emerald-800/30">
              <img 
                src={user.avatar} 
                alt={user.name}
                className="w-10 h-10 rounded-full border-2 border-emerald-400"
              />
              <div className="flex-1 min-w-0">
                <p className="font-medium truncate">{user.name}</p>
                <p className="text-emerald-300 text-sm">{user.plan} Plan</p>
              </div>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <div className={`lg:pl-64 transition-all duration-200 ${sidebarOpen ? 'pl-0' : ''}`}>
        {/* Top Navigation */}
        <header className="bg-white border-b border-slate-200 sticky top-0 z-30">
          <div className="px-6 py-4 flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <button
                onClick={() => setSidebarOpen(!sidebarOpen)}
                className="lg:hidden p-2 rounded-lg hover:bg-slate-100"
              >
                {sidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
              </button>
              
              {/* Breadcrumb */}
              <div className="flex items-center space-x-2 text-sm text-slate-600">
                <span>Dashboard</span>
                <span>/</span>
                <span className="font-medium text-slate-900">AI Insights</span>
              </div>
            </div>

            <div className="flex items-center space-x-4">
              {/* AI Agent Status */}
              <div className="hidden md:flex items-center space-x-2 px-4 py-2 bg-emerald-50 rounded-full">
                <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></div>
                <span className="text-sm font-medium text-emerald-700">
                  AI Agents Active
                </span>
              </div>

              {/* Notifications */}
              <button className="relative p-2 rounded-lg hover:bg-slate-100">
                <Bell className="w-5 h-5" />
                <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full"></span>
              </button>

              {/* Quick Actions */}
              <button className="bg-linear-to-r from-emerald-600 to-teal-600 text-white px-4 py-2 rounded-lg font-medium hover:shadow-lg transition-shadow">
                Ask AI Agent
              </button>
            </div>
          </div>
        </header>

        {/* Main Dashboard Content */}
        <main className="p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default DashboardLayout;