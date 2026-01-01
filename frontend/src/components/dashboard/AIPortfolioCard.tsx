// src/components/dashboard/AIPortfolioCard.tsx
import { PieChart, TrendingUp, AlertCircle } from 'lucide-react';
import { Cell, Pie, PieChart as RechartsPieChart, ResponsiveContainer, Tooltip } from 'recharts';

const AIPortfolioCard = () => {
  // Mock portfolio data
  const portfolioData = [
    { name: 'Equity', value: 65, color: '#10b981' },
    { name: 'Mutual Funds', value: 20, color: '#3b82f6' },
    { name: 'Bonds', value: 10, color: '#8b5cf6' },
    { name: 'Gold', value: 5, color: '#f59e0b' },
  ];

  const aiRecommendations = [
    { action: 'Increase', stock: 'RELIANCE', amount: '₹50,000', reason: 'Strong AI prediction' },
    { action: 'Reduce', stock: 'HDFC', amount: '₹25,000', reason: 'Market volatility' },
    { action: 'Hold', stock: 'TCS', amount: 'Current', reason: 'Stable growth' },
  ];

  return (
    <div className="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden">
      <div className="p-6 border-b border-slate-200">
        <div className="flex justify-between items-center">
          <div>
            <h3 className="text-lg font-semibold text-slate-900">AI-Optimized Portfolio</h3>
            <p className="text-sm text-slate-600">Auto-balanced by AI agents</p>
          </div>
          <div className="flex items-center gap-2">
            <PieChart className="w-5 h-5 text-emerald-600" />
            <span className="text-emerald-700 font-medium">+2.4% Today</span>
          </div>
        </div>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-2">
        {/* Portfolio Chart */}
        <div className="p-6 border-r border-slate-200">
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <RechartsPieChart>
                <Pie
                  data={portfolioData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {portfolioData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip 
                  formatter={(value) => [`${value}%`, 'Allocation']}
                  contentStyle={{ 
                    borderRadius: '8px', 
                    border: '1px solid #e2e8f0',
                    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
                  }}
                />
              </RechartsPieChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-2 gap-4 mt-4">
            {portfolioData.map((item, index) => (
              <div key={index} className="flex items-center">
                <div 
                  className="w-3 h-3 rounded-full mr-2" 
                  style={{ backgroundColor: item.color }}
                ></div>
                <div>
                  <p className="text-sm font-medium">{item.name}</p>
                  <p className="text-sm text-slate-600">{item.value}%</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* AI Recommendations */}
        <div className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h4 className="font-semibold text-slate-900">AI Recommendations</h4>
            <AlertCircle className="w-5 h-5 text-amber-500" />
          </div>
          
          <div className="space-y-4">
            {aiRecommendations.map((rec, index) => (
              <div key={index} className="flex items-center justify-between p-3 bg-slate-50 rounded-lg">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <div className={`
                      px-2 py-1 rounded text-xs font-medium
                      ${rec.action === 'Increase' ? 'bg-emerald-100 text-emerald-800' : 
                        rec.action === 'Reduce' ? 'bg-red-100 text-red-800' : 
                        'bg-amber-100 text-amber-800'}
                    `}>
                      {rec.action}
                    </div>
                    <span className="font-medium">{rec.stock}</span>
                  </div>
                  <p className="text-sm text-slate-600">{rec.reason}</p>
                </div>
                <div className="text-right">
                  <p className="font-medium">{rec.amount}</p>
                  <button className="mt-2 text-sm text-emerald-600 hover:text-emerald-700 font-medium">
                    Execute →
                  </button>
                </div>
              </div>
            ))}
          </div>

          <div className="mt-6 p-4 bg-emerald-50 rounded-xl">
            <div className="flex items-center gap-3">
              <TrendingUp className="w-5 h-5 text-emerald-600" />
              <div>
                <p className="font-medium text-emerald-900">AI Prediction</p>
                <p className="text-sm text-emerald-700">
                  Expected portfolio growth: 12-15% in next quarter
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AIPortfolioCard;