// src/components/dashboard/StockPredictions.tsx
import React from 'react';
import { TrendingUp, TrendingDown, Minus } from 'lucide-react';

export interface Prediction {
  id: number;
  stock: string;
  prediction: 'Bullish' | 'Bearish' | 'Neutral';
  confidence: number;
  reasoning: string;
  timeframe: string;
}

interface StockPredictionsProps {
  predictions: Prediction[];
}

const StockPredictions: React.FC<StockPredictionsProps> = ({ predictions }) => {
  const getPredictionIcon = (prediction: string) => {
    switch (prediction) {
      case 'Bullish':
        return <TrendingUp className="w-5 h-5 text-emerald-600" />;
      case 'Bearish':
        return <TrendingDown className="w-5 h-5 text-red-600" />;
      default:
        return <Minus className="w-5 h-5 text-amber-600" />;
    }
  };

  const getPredictionColor = (prediction: string) => {
    switch (prediction) {
      case 'Bullish':
        return 'bg-emerald-50 text-emerald-800 border-emerald-200';
      case 'Bearish':
        return 'bg-red-50 text-red-800 border-red-200';
      default:
        return 'bg-amber-50 text-amber-800 border-amber-200';
    }
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 80) return 'text-emerald-600';
    if (confidence >= 60) return 'text-amber-600';
    return 'text-red-600';
  };

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-slate-200">
            <th className="text-left py-3 px-6 text-sm font-medium text-slate-600">Stock</th>
            <th className="text-left py-3 px-6 text-sm font-medium text-slate-600">Prediction</th>
            <th className="text-left py-3 px-6 text-sm font-medium text-slate-600">Confidence</th>
            <th className="text-left py-3 px-6 text-sm font-medium text-slate-600">AI Reasoning</th>
            <th className="text-left py-3 px-6 text-sm font-medium text-slate-600">Timeframe</th>
            <th className="text-left py-3 px-6 text-sm font-medium text-slate-600">Action</th>
          </tr>
        </thead>
        <tbody>
          {predictions.map((pred) => (
            <tr key={pred.id} className="border-b border-slate-100 hover:bg-slate-50">
              <td className="py-4 px-6">
                <div className="font-bold text-slate-900">{pred.stock}</div>
                <div className="text-sm text-slate-500">NSE</div>
              </td>
              <td className="py-4 px-6">
                <div className="flex items-center gap-2">
                  {getPredictionIcon(pred.prediction)}
                  <span className={`px-3 py-1 rounded-full text-xs font-medium border ${getPredictionColor(pred.prediction)}`}>
                    {pred.prediction}
                  </span>
                </div>
              </td>
              <td className="py-4 px-6">
                <div className={`font-bold ${getConfidenceColor(pred.confidence)}`}>
                  {pred.confidence}%
                </div>
                <div className="w-full bg-slate-200 rounded-full h-1.5 mt-1">
                  <div 
                    className={`h-1.5 rounded-full ${
                      pred.confidence >= 80 ? 'bg-emerald-500' : 
                      pred.confidence >= 60 ? 'bg-amber-500' : 
                      'bg-red-500'
                    }`}
                    style={{ width: `${pred.confidence}%` }}
                  ></div>
                </div>
              </td>
              <td className="py-4 px-6">
                <div className="text-sm text-slate-700 max-w-xs">{pred.reasoning}</div>
              </td>
              <td className="py-4 px-6">
                <span className="px-3 py-1 bg-slate-100 text-slate-700 rounded-full text-sm">
                  {pred.timeframe}
                </span>
              </td>
              <td className="py-4 px-6">
                <button className="text-emerald-600 hover:text-emerald-700 font-medium text-sm">
                  View Details →
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      
      <div className="p-4 border-t border-slate-200">
        <div className="flex items-center justify-between">
          <p className="text-sm text-slate-600">
            Powered by Prophet forecasting & FinBERT sentiment analysis
          </p>
          <button className="text-emerald-600 hover:text-emerald-700 font-medium">
            View All Predictions →
          </button>
        </div>
      </div>
    </div>
  );
};

export default StockPredictions;