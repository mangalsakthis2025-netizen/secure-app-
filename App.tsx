import React, { useState, useEffect } from 'react';
import { Shield, Lock, Activity, User, LogOut } from 'lucide-react';
import { LoginForm } from './components/LoginForm';
import { Dashboard } from './components/Dashboard';

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState<{ name: string; role: string } | null>(null);
  const [isDarkMode, setIsDarkMode] = useState(true); // Default to dark mode for the "hacker" feel

  const handleLogin = (userData: { name: string; role: string }) => {
    setIsAuthenticated(true);
    setUser(userData);
  };

  const handleLogout = () => {
    setIsAuthenticated(false);
    setUser(null);
  };

  const toggleTheme = () => {
    setIsDarkMode(!isDarkMode);
  };

  return (
    <div className={`min-h-screen font-sans ${isDarkMode ? 'dark' : ''}`}>
      {isAuthenticated ? (
        <Dashboard 
          user={user} 
          onLogout={handleLogout} 
          isDarkMode={isDarkMode} 
          onToggleTheme={toggleTheme} 
        />
      ) : (
        <LoginForm 
          onLogin={handleLogin} 
          isDarkMode={isDarkMode}
          onToggleTheme={toggleTheme}
        />
      )}
    </div>
  );
}
