// src/pages/Dashboard.tsx
import React, { useState, useRef, useEffect } from 'react';
import { 
  TrendingUp, 
  TrendingDown, 
  PieChart, 
  Shield,
  Zap,
  Brain,
  Bell,
  ChevronRight,
  Download,
  LineChart,
  AlertCircle,
  Target,
  Clock,
  IndianRupee,
  BarChart3,
  RefreshCw,
  MessageSquare,
  Filter,
  Eye,
  Settings,
  LogOut,
  Send,
  X,
  Minimize2,
  Maximize2,
  User,
  CreditCard,
  HelpCircle
} from 'lucide-react';
import { useAuth } from '../auth/AuthContext';

// Chatbot Component
const AIChatWidget = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [isMinimized, setIsMinimized] = useState(false);
  const [message, setMessage] = useState('');

  if (!isOpen) {
    return (
      <button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-6 right-6 bg-gradient-to-r from-emerald-600 to-teal-600 text-white p-3 rounded-full shadow-xl hover:shadow-2xl transition-all duration-200 hover:scale-105 z-50"
      >
        <MessageSquare className="w-5 h-5" />
      </button>
    );
  }

  return (
    <div className={`
      fixed bottom-6 right-6 w-80 bg-white rounded-xl shadow-2xl border border-gray-200 
      transition-all duration-300 ${isMinimized ? 'h-12' : 'h-96'}
      z-50
    `}>
      {/* Header */}
      <div className="flex items-center justify-between p-3 border-b border-gray-200 bg-gradient-to-r from-emerald-50 to-teal-50">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 bg-gradient-to-r from-emerald-500 to-teal-500 rounded-full flex items-center justify-center">
            <Brain className="w-3 h-3 text-white" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-gray-900">AI Assistant</h3>
          </div>
        </div>
        <div className="flex items-center gap-1">
          <button 
            onClick={() => setIsMinimized(!isMinimized)}
            className="p-1 hover:bg-gray-100 rounded"
          >
            {isMinimized ? <Maximize2 className="w-3 h-3" /> : <Minimize2 className="w-3 h-3" />}
          </button>
          <button 
            onClick={() => setIsOpen(false)}
            className="p-1 hover:bg-gray-100 rounded"
          >
            <X className="w-3 h-3" />
          </button>
        </div>
      </div>

      {!isMinimized && (
        <>
          {/* Messages */}
          <div className="h-64 overflow-y-auto p-3 space-y-3">
            <div className="flex justify-start">
              <div className="bg-gray-100 rounded-lg rounded-bl-none p-3 max-w-[80%]">
                <p className="text-sm text-gray-800">Hello! I'm your DhanSaathi AI assistant. How can I help with your investments today?</p>
              </div>
            </div>
          </div>

          {/* Input */}
          <div className="p-3 border-t border-gray-200">
            <div className="flex gap-2">
              <input
                type="text"
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Ask about stocks or portfolio..."
                className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500"
              />
              <button className="bg-emerald-600 text-white p-2 rounded-lg hover:bg-emerald-700">
                <Send className="w-4 h-4" />
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

const Dashboard = () => {
  const { user, logout } = useAuth();
  const [showProfileDropdown, setShowProfileDropdown] = useState(false);
  const profileDropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (profileDropdownRef.current && !profileDropdownRef.current.contains(event.target as Node)) {
        setShowProfileDropdown(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  // Financial metrics
  const financialMetrics = [
    { 
      title: 'Portfolio Value', 
      value: '₹12.45L', 
      change: '+12.4%',
      icon: IndianRupee,
      color: 'text-emerald-600',
      bgColor: 'bg-emerald-50'
    },
    { 
      title: "Today's P&L", 
      value: '₹8,450', 
      change: '+1.8%',
      icon: TrendingUp,
      color: 'text-green-600',
      bgColor: 'bg-green-50'
    },
    { 
      title: 'AI Accuracy', 
      value: '87%', 
      change: '+2.1%',
      icon: Brain,
      color: 'text-blue-600',
      bgColor: 'bg-blue-50'
    },
    { 
      title: 'Risk Score', 
      value: '6.2/10', 
      icon: Shield,
      color: 'text-amber-600',
      bgColor: 'bg-amber-50'
    },
  ];

  // Portfolio allocation
  const portfolioAllocation = [
    { name: 'Equity', value: 65, color: '#059669', amount: '₹8.09L' },
    { name: 'Mutual Funds', value: 20, color: '#2563eb', amount: '₹2.49L' },
    { name: 'Bonds', value: 10, color: '#7c3aed', amount: '₹1.24L' },
    { name: 'Gold', value: 5, color: '#d97706', amount: '₹62,250' },
  ];

  // NSE Top gainers
  const topGainers = [
    { symbol: 'RELIANCE', name: 'Reliance Industries', price: '₹2,845.60', change: '+2.8%', volume: '42.5L' },
    { symbol: 'TCS', name: 'Tata Consultancy', price: '₹3,892.15', change: '+1.9%', volume: '18.2L' },
    { symbol: 'INFY', name: 'Infosys', price: '₹1,685.40', change: '+3.2%', volume: '35.8L' },
    { symbol: 'HDFCBANK', name: 'HDFC Bank', price: '₹1,582.30', change: '+1.5%', volume: '28.3L' },
  ];

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Top Navigation - Wider like BSE/NSE */}
      <div className="bg-white border-b border-gray-200">
        <div className="max-w-screen-2xl mx-auto px-6">
          <div className="flex items-center justify-between py-3">
            {/* Left: Logo and Navigation */}
            <div className="flex items-center space-x-8">
              <div className="flex items-center space-x-3">
                <div className="w-8 h-8 bg-gradient-to-r from-emerald-600 to-teal-600 rounded-lg flex items-center justify-center">
                  <IndianRupee className="w-4 h-4 text-white" />
                </div>
                <div>
                  <h1 className="text-lg font-bold text-gray-900">DhanSaathi</h1>
                  <p className="text-xs text-gray-500">AI Financial Platform</p>
                </div>
              </div>

              {/* Navigation Links */}
              <div className="hidden lg:flex items-center space-x-6">
                <a href="#" className="text-sm font-medium text-gray-700 hover:text-emerald-600">Dashboard</a>
                <a href="#" className="text-sm font-medium text-gray-700 hover:text-emerald-600">Portfolio</a>
                <a href="#" className="text-sm font-medium text-gray-700 hover:text-emerald-600">Markets</a>
                <a href="#" className="text-sm font-medium text-gray-700 hover:text-emerald-600">Reports</a>
                <a href="#" className="text-sm font-medium text-gray-700 hover:text-emerald-600">AI Insights</a>
              </div>
            </div>

            {/* Right: Market Data and User */}
            <div className="flex items-center space-x-6">
              {/* Live Market Data */}
              <div className="hidden xl:flex items-center space-x-6">
                <div className="text-right">
                  <div className="text-xs text-gray-500">NIFTY 50</div>
                  <div className="text-sm font-semibold text-green-600">22,142.35 <span className="text-xs">+1.2%</span></div>
                </div>
                <div className="text-right">
                  <div className="text-xs text-gray-500">SENSEX</div>
                  <div className="text-sm font-semibold text-green-600">73,128.77 <span className="text-xs">+1.4%</span></div>
                </div>
                <div className="text-right">
                  <div className="text-xs text-gray-500">BANK NIFTY</div>
                  <div className="text-sm font-semibold text-green-600">46,892.60 <span className="text-xs">+0.8%</span></div>
                </div>
              </div>

              {/* User Actions */}
              <div className="flex items-center space-x-4">
                <button className="relative p-1.5 hover:bg-gray-100 rounded">
                  <Bell className="w-4 h-4 text-gray-600" />
                  <span className="absolute top-1 right-1 w-1.5 h-1.5 bg-red-500 rounded-full"></span>
                </button>
                
                {/* Profile Dropdown */}
                <div className="relative" ref={profileDropdownRef}>
                  <button 
                    onClick={() => setShowProfileDropdown(!showProfileDropdown)}
                    className="flex items-center space-x-2 hover:bg-gray-100 rounded-lg p-1"
                  >
                    <div className="w-8 h-8 bg-emerald-600 rounded-full flex items-center justify-center text-white text-sm font-semibold">
                      {user?.name?.charAt(0) || 'J'}
                    </div>
                    <div className="hidden md:block">
                      <p className="text-sm font-medium text-gray-900">{user?.name || 'Jaldhi Shukla'}</p>
                      <p className="text-xs text-gray-500">Premium Investor</p>
                    </div>
                    <svg 
                      className={`w-4 h-4 text-gray-500 transition-transform ${showProfileDropdown ? 'rotate-180' : ''}`}
                      fill="none" 
                      stroke="currentColor" 
                      viewBox="0 0 24 24"
                    >
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                    </svg>
                  </button>

                  {/* Dropdown Menu */}
                  {showProfileDropdown && (
                    <div className="absolute right-0 mt-2 w-48 bg-white rounded-lg shadow-xl border border-gray-200 py-2 z-50">
                      <div className="px-4 py-3 border-b border-gray-100">
                        <p className="text-sm font-medium text-gray-900">{user?.name || 'Jaldhi Shukla'}</p>
                        <p className="text-xs text-gray-500 truncate">{user?.email || 'jaldhi@example.com'}</p>
                      </div>
                      
                      <div className="py-1">
                        <a 
                          href="#" 
                          className="flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                        >
                          <User className="w-4 h-4 mr-3 text-gray-500" />
                          My Profile
                        </a>
                        <a 
                          href="#" 
                          className="flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                        >
                          <CreditCard className="w-4 h-4 mr-3 text-gray-500" />
                          Subscription
                        </a>
                        <a 
                          href="#" 
                          className="flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                        >
                          <Settings className="w-4 h-4 mr-3 text-gray-500" />
                          Settings
                        </a>
                        <a 
                          href="#" 
                          className="flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                        >
                          <HelpCircle className="w-4 h-4 mr-3 text-gray-500" />
                          Help & Support
                        </a>
                      </div>
                      
                      <div className="border-t border-gray-100 py-1">
                        <button
                          onClick={logout}
                          className="flex items-center w-full px-4 py-2 text-sm text-red-600 hover:bg-red-50"
                        >
                          <LogOut className="w-4 h-4 mr-3" />
                          Logout
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Main Dashboard - Wide Layout */}
      <div className="max-w-screen-2xl mx-auto px-6 py-4">
        {/* Welcome and Quick Stats */}
        <div className="mb-6">
          <div className="flex justify-between items-center">
            <div>
              <h1 className="text-xl font-bold text-gray-900">Welcome back, {user?.name?.split(' ')[0] || 'Jaldhi'}</h1>
              <div className="flex items-center text-sm text-gray-500 mt-1">
                <Clock className="w-3 h-3 mr-1" />
                {new Date().toLocaleDateString('en-IN', { 
                  weekday: 'short', 
                  year: 'numeric', 
                  month: 'short', 
                  day: 'numeric' 
                })} • Last updated: Just now
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <button className="px-3 py-1.5 bg-gray-100 hover:bg-gray-200 text-gray-700 text-sm rounded-lg flex items-center">
                <RefreshCw className="w-3 h-3 mr-1" />
                Refresh
              </button>
              <button className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white text-sm rounded-lg flex items-center">
                <MessageSquare className="w-3 h-3 mr-1" />
                Ask AI
              </button>
            </div>
          </div>
        </div>

        {/* Financial Metrics Grid - 4 columns */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          {financialMetrics.map((metric, index) => {
            const Icon = metric.icon;
            return (
              <div key={index} className="bg-white rounded-lg border border-gray-200 p-4">
                <div className="flex items-start justify-between">
                  <div>
                    <p className="text-xs text-gray-500 mb-1">{metric.title}</p>
                    <p className="text-lg font-bold text-gray-900">{metric.value}</p>
                    {metric.change && (
                      <div className={`flex items-center text-xs mt-1 ${
                        metric.change.startsWith('+') ? 'text-green-600' : 'text-red-600'
                      }`}>
                        {metric.change.startsWith('+') ? 
                          <TrendingUp className="w-3 h-3 mr-1" /> : 
                          <TrendingDown className="w-3 h-3 mr-1" />
                        }
                        {metric.change}
                      </div>
                    )}
                  </div>
                  <div className={`p-2 rounded ${metric.bgColor}`}>
                    <Icon className={`w-4 h-4 ${metric.color}`} />
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Main Content Grid - Wider Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column - 2/3 width */}
          <div className="lg:col-span-2 space-y-6">
            {/* Portfolio Overview - Wider Card */}
            <div className="bg-white rounded-lg border border-gray-200">
              <div className="px-5 py-4 border-b border-gray-200">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="font-semibold text-gray-900">Portfolio Overview</h3>
                    <p className="text-sm text-gray-500">Auto-balanced by AI agents</p>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="px-3 py-1 bg-emerald-100 text-emerald-800 text-xs font-medium rounded-full">
                      +2.4% today
                    </span>
                    <button className="text-sm text-blue-600 hover:text-blue-700">View details</button>
                  </div>
                </div>
              </div>
              
              <div className="p-5">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  {/* Allocation Chart */}
                  <div className="md:col-span-2">
                    <h4 className="text-sm font-medium text-gray-900 mb-3">Portfolio Allocation</h4>
                    <div className="space-y-3">
                      {portfolioAllocation.map((item, index) => (
                        <div key={index} className="flex items-center justify-between">
                          <div className="flex items-center flex-1">
                            <div 
                              className="w-3 h-3 rounded mr-3" 
                              style={{ backgroundColor: item.color }}
                            ></div>
                            <span className="text-sm text-gray-700">{item.name}</span>
                            <div className="ml-4 w-48 bg-gray-200 rounded-full h-2">
                              <div 
                                className="h-2 rounded-full"
                                style={{ 
                                  backgroundColor: item.color,
                                  width: `${item.value}%`
                                }}
                              ></div>
                            </div>
                          </div>
                          <div className="text-right ml-4">
                            <div className="text-sm font-medium text-gray-900">{item.amount}</div>
                            <div className="text-xs text-gray-500">{item.value}%</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Performance Stats */}
                  <div>
                    <h4 className="text-sm font-medium text-gray-900 mb-3">Performance</h4>
                    <div className="space-y-3">
                      <div className="p-3 bg-green-50 rounded-lg">
                        <div className="flex justify-between items-center">
                          <div>
                            <p className="text-xs text-gray-600">1D Return</p>
                            <p className="text-sm font-bold text-green-700">+₹8,450</p>
                          </div>
                          <span className="text-xs text-green-600">+1.8%</span>
                        </div>
                      </div>
                      
                      <div className="p-3 bg-blue-50 rounded-lg">
                        <div className="flex justify-between items-center">
                          <div>
                            <p className="text-xs text-gray-600">1M Return</p>
                            <p className="text-sm font-bold text-blue-700">+₹52,140</p>
                          </div>
                          <span className="text-xs text-blue-600">+4.2%</span>
                        </div>
                      </div>
                      
                      <div className="p-3 bg-purple-50 rounded-lg">
                        <div className="flex justify-between items-center">
                          <div>
                            <p className="text-xs text-gray-600">1Y Return</p>
                            <p className="text-sm font-bold text-purple-700">+₹1.98L</p>
                          </div>
                          <span className="text-xs text-purple-600">+18.7%</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Market Data Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Market Indices */}
              <div className="bg-white rounded-lg border border-gray-200">
                <div className="px-4 py-3 border-b border-gray-200 flex justify-between items-center">
                  <h3 className="font-semibold text-gray-900">Market Indices</h3>
                  <span className="text-xs text-green-600 font-medium">Live</span>
                </div>
                <div className="p-4">
                  {[
                    { name: 'NIFTY 50', value: '22,142.35', change: '+1.2%', points: '+263.15' },
                    { name: 'SENSEX', value: '73,128.77', change: '+1.4%', points: '+1,028.41' },
                    { name: 'BANK NIFTY', value: '46,892.60', change: '+0.8%', points: '+374.15' },
                    { name: 'NIFTY IT', value: '37,856.25', change: '+2.1%', points: '+778.30' },
                  ].map((index, i) => (
                    <div key={i} className="flex items-center justify-between py-3 border-b border-gray-100 last:border-0">
                      <div>
                        <div className="text-sm font-medium text-gray-900">{index.name}</div>
                      </div>
                      <div className="text-right">
                        <div className="text-sm font-medium text-gray-900">{index.value}</div>
                        <div className="text-xs text-green-600">{index.change} ({index.points})</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Top Gainers */}
              <div className="bg-white rounded-lg border border-gray-200">
                <div className="px-4 py-3 border-b border-gray-200 flex justify-between items-center">
                  <h3 className="font-semibold text-gray-900">Top Gainers</h3>
                  <button className="text-xs text-blue-600">View all</button>
                </div>
                <div className="p-4">
                  {topGainers.map((stock, i) => (
                    <div key={i} className="flex items-center justify-between py-3 border-b border-gray-100 last:border-0">
                      <div className="flex items-center">
                        <div className="w-8 h-8 bg-green-100 text-green-800 rounded text-xs flex items-center justify-center font-bold mr-3">
                          {stock.symbol.charAt(0)}
                        </div>
                        <div>
                          <div className="text-sm font-medium text-gray-900">{stock.symbol}</div>
                          <div className="text-xs text-gray-500">{stock.name}</div>
                        </div>
                      </div>
                      <div className="text-right">
                        <div className="text-sm font-medium text-gray-900">{stock.price}</div>
                        <div className="text-xs text-green-600">{stock.change}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* AI Predictions Table - Wide */}
            <div className="bg-white rounded-lg border border-gray-200">
              <div className="px-5 py-4 border-b border-gray-200 flex justify-between items-center">
                <div>
                  <h3 className="font-semibold text-gray-900">AI Stock Predictions</h3>
                  <p className="text-sm text-gray-500">Powered by Prophet & FinBERT models</p>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="px-3 py-1 bg-emerald-100 text-emerald-800 text-xs font-medium rounded-full">
                    87% Accuracy
                  </span>
                  <button className="p-1.5 hover:bg-gray-100 rounded">
                    <Filter className="w-3 h-3" />
                  </button>
                </div>
              </div>
              
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-5 py-3 text-left text-xs font-medium text-gray-500">Stock</th>
                      <th className="px-5 py-3 text-left text-xs font-medium text-gray-500">Action</th>
                      <th className="px-5 py-3 text-left text-xs font-medium text-gray-500">Target Price</th>
                      <th className="px-5 py-3 text-left text-xs font-medium text-gray-500">Current</th>
                      <th className="px-5 py-3 text-left text-xs font-medium text-gray-500">Confidence</th>
                      <th className="px-5 py-3 text-left text-xs font-medium text-gray-500">Horizon</th>
                      <th className="px-5 py-3 text-left text-xs font-medium text-gray-500">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[
                      { stock: 'RELIANCE', action: 'BUY', target: '₹3,000', current: '₹2,845', confidence: 85, horizon: '1 week' },
                      { stock: 'TATAMOTORS', action: 'STRONG BUY', target: '₹920', current: '₹845', confidence: 91, horizon: '2 weeks' },
                      { stock: 'BAJFINANCE', action: 'HOLD', target: '₹7,800', current: '₹7,245', confidence: 78, horizon: '1 month' },
                      { stock: 'WIPRO', action: 'SELL', target: '₹480', current: '₹520', confidence: 72, horizon: '1 week' },
                      { stock: 'HCLTECH', action: 'BUY', target: '₹1,650', current: '₹1,542', confidence: 82, horizon: '3 weeks' },
                    ].map((prediction, i) => (
                      <tr key={i} className="border-t border-gray-100 hover:bg-gray-50">
                        <td className="px-5 py-3 font-medium text-gray-900">{prediction.stock}</td>
                        <td className="px-5 py-3">
                          <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                            prediction.action.includes('BUY') 
                              ? 'bg-green-100 text-green-800' 
                              : prediction.action === 'HOLD'
                              ? 'bg-amber-100 text-amber-800'
                              : 'bg-red-100 text-red-800'
                          }`}>
                            {prediction.action}
                          </span>
                        </td>
                        <td className="px-5 py-3 font-medium text-gray-900">{prediction.target}</td>
                        <td className="px-5 py-3 text-gray-600">{prediction.current}</td>
                        <td className="px-5 py-3">
                          <div className="flex items-center">
                            <div className="w-24 bg-gray-200 rounded-full h-1.5 mr-3">
                              <div 
                                className={`h-1.5 rounded-full ${
                                  prediction.confidence >= 85 ? 'bg-green-500' : 
                                  prediction.confidence >= 70 ? 'bg-amber-500' : 
                                  'bg-red-500'
                                }`}
                                style={{ width: `${prediction.confidence}%` }}
                              ></div>
                            </div>
                            <span className="text-sm">{prediction.confidence}%</span>
                          </div>
                        </td>
                        <td className="px-5 py-3 text-gray-600">{prediction.horizon}</td>
                        <td className="px-5 py-3">
                          <button className="text-sm text-blue-600 hover:text-blue-700">
                            Execute
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Right Column - 1/3 width */}
          <div className="space-y-6">
            {/* AI Quick Actions */}
            <div className="bg-gradient-to-br from-emerald-900 to-teal-800 rounded-lg p-5 text-white">
              <h3 className="font-semibold mb-4">AI Quick Actions</h3>
              <div className="space-y-2">
                <button className="w-full bg-white/10 hover:bg-white/20 text-sm py-3 px-4 rounded-lg flex items-center justify-between">
                  <span>Generate Portfolio Report</span>
                  <Download className="w-4 h-4" />
                </button>
                <button className="w-full bg-white/10 hover:bg-white/20 text-sm py-3 px-4 rounded-lg flex items-center justify-between">
                  <span>Ask Financial Advice</span>
                  <MessageSquare className="w-4 h-4" />
                </button>
                <button className="w-full bg-white/10 hover:bg-white/20 text-sm py-3 px-4 rounded-lg flex items-center justify-between">
                  <span>Risk Assessment</span>
                  <Shield className="w-4 h-4" />
                </button>
                <button className="w-full bg-white/10 hover:bg-white/20 text-sm py-3 px-4 rounded-lg flex items-center justify-between">
                  <span>Market Analysis</span>
                  <BarChart3 className="w-4 h-4" />
                </button>
              </div>
              
              <div className="mt-6 pt-4 border-t border-white/20">
                <div className="flex items-center justify-between mb-2">
                  <div className="text-sm text-emerald-200">AI Agents Status</div>
                  <div className="flex items-center gap-1">
                    <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                    <span className="text-xs">All Active</span>
                  </div>
                </div>
                <div className="grid grid-cols-3 gap-2 text-xs">
                  <div className="text-center p-2 bg-white/10 rounded">
                    <div className="text-emerald-300">Market</div>
                    <div className="text-green-400">●</div>
                  </div>
                  <div className="text-center p-2 bg-white/10 rounded">
                    <div className="text-emerald-300">Risk</div>
                    <div className="text-green-400">●</div>
                  </div>
                  <div className="text-center p-2 bg-white/10 rounded">
                    <div className="text-emerald-300">News</div>
                    <div className="text-amber-400">●</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Recent Transactions */}
            <div className="bg-white rounded-lg border border-gray-200">
              <div className="px-4 py-3 border-b border-gray-200 flex justify-between items-center">
                <h3 className="font-semibold text-gray-900">Recent Transactions</h3>
                <button className="text-xs text-blue-600">View all</button>
              </div>
              
              <div className="p-4">
                {[
                  { type: 'BUY', stock: 'RELIANCE', qty: '25', amount: '₹71,140', time: '10:24 AM', status: 'Completed' },
                  { type: 'SELL', stock: 'TCS', qty: '10', amount: '₹38,921', time: '09:45 AM', status: 'Completed' },
                  { type: 'BUY', stock: 'INFY', qty: '40', amount: '₹67,416', time: 'Yesterday', status: 'Pending' },
                  { type: 'BUY', stock: 'HDFCBANK', qty: '25', amount: '₹39,557', time: 'Yesterday', status: 'Completed' },
                  { type: 'BUY', stock: 'TATAMOTORS', qty: '50', amount: '₹42,250', time: '2 days ago', status: 'Completed' },
                ].map((txn, i) => (
                  <div key={i} className="flex items-center justify-between py-3 border-b border-gray-100 last:border-0">
                    <div className="flex items-center">
                      <div className={`w-7 h-7 rounded text-xs flex items-center justify-center font-bold mr-3 ${
                        txn.type === 'BUY' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                      }`}>
                        {txn.type.charAt(0)}
                      </div>
                      <div>
                        <div className="text-sm font-medium text-gray-900">{txn.stock}</div>
                        <div className="text-xs text-gray-500">{txn.qty} shares • {txn.time}</div>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-sm font-medium text-gray-900">{txn.amount}</div>
                      <span className={`text-xs px-2 py-0.5 rounded-full ${
                        txn.status === 'Completed' 
                          ? 'bg-green-100 text-green-800' 
                          : 'bg-amber-100 text-amber-800'
                      }`}>
                        {txn.status}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Market Sentiment & News */}
            <div className="bg-white rounded-lg border border-gray-200">
              <div className="px-4 py-3 border-b border-gray-200">
                <h3 className="font-semibold text-gray-900">Market Sentiment</h3>
              </div>
              <div className="p-4">
                <div className="mb-4">
                  <div className="flex justify-between text-sm text-gray-600 mb-2">
                    <span>Bullish: 65%</span>
                    <span>Bearish: 20%</span>
                    <span>Neutral: 15%</span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div 
                      className="bg-green-500 h-2 rounded-full"
                      style={{ width: '65%' }}
                    ></div>
                    <div 
                      className="bg-red-500 h-2 rounded-full -ml-1"
                      style={{ width: '20%' }}
                    ></div>
                  </div>
                </div>
                
                <div className="space-y-3">
                  <div className="p-3 bg-blue-50 rounded-lg">
                    <div className="flex items-start">
                      <AlertCircle className="w-4 h-4 text-blue-500 mt-0.5 mr-2" />
                      <div>
                        <p className="text-sm font-medium text-blue-900">Tech Sector Alert</p>
                        <p className="text-xs text-blue-700 mt-1">IT stocks showing 15% YTD growth</p>
                      </div>
                    </div>
                  </div>
                  
                  <div className="p-3 bg-amber-50 rounded-lg">
                    <div className="flex items-start">
                      <AlertCircle className="w-4 h-4 text-amber-500 mt-0.5 mr-2" />
                      <div>
                        <p className="text-sm font-medium text-amber-900">Interest Rates</p>
                        <p className="text-xs text-amber-700 mt-1">RBI meeting outcome expected tomorrow</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Quick Stats */}
            <div className="bg-white rounded-lg border border-gray-200 p-4">
              <h4 className="text-sm font-medium text-gray-900 mb-3">Portfolio Metrics</h4>
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-gray-50 p-3 rounded-lg">
                  <div className="text-xs text-gray-500">Sharpe Ratio</div>
                  <div className="text-sm font-bold text-green-600">1.85</div>
                </div>
                <div className="bg-gray-50 p-3 rounded-lg">
                  <div className="text-xs text-gray-500">Volatility</div>
                  <div className="text-sm font-bold text-gray-900">12.4%</div>
                </div>
                <div className="bg-gray-50 p-3 rounded-lg">
                  <div className="text-xs text-gray-500">Max Drawdown</div>
                  <div className="text-sm font-bold text-red-600">-8.2%</div>
                </div>
                <div className="bg-gray-50 p-3 rounded-lg">
                  <div className="text-xs text-gray-500">Win Rate</div>
                  <div className="text-sm font-bold text-green-600">72%</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="mt-8 pt-6 border-t border-gray-200">
          <div className="text-center text-xs text-gray-500">
            <p>DhanSaathi AI Financial Platform • Real-time data from NSE & BSE • Broker: Zerodha</p>
            <p className="mt-1">© 2024 DhanSaathi. Empowering Aatmanirbhar Bharat with AI-driven financial insights.</p>
          </div>
        </div>
      </div>

      {/* Chatbot Widget */}
      <AIChatWidget />
    </div>
  );
};

export default Dashboard;