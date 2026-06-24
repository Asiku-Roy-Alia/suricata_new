import React from 'react';
import ReactDOM from 'react-dom/client';
import HybridIDSDashboard from './HybridIDSDashboard';   // ← Correct import

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <HybridIDSDashboard />
  </React.StrictMode>
);