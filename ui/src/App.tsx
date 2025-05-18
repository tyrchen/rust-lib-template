import { useState } from 'react';

function App() {
  const [isDarkMode, setIsDarkMode] = useState(false);

  return (
    <div className={`min-h-screen ${isDarkMode ? 'dark' : ''}`}>
      <div className="bg-background text-foreground">
        {/* Hero Section */}
        <div className="container mx-auto px-4 py-16">
          <div className="text-center">
            <h1 className="text-4xl font-bold tracking-tight sm:text-6xl">
              Welcome to Our Platform
            </h1>
            <p className="mt-6 text-lg leading-8 text-muted-foreground">
              A modern solution for all your needs. Built with React, TypeScript, and Tailwind CSS.
            </p>
            <div className="mt-10 flex items-center justify-center gap-x-6">
              <button
                onClick={() => setIsDarkMode(!isDarkMode)}
                className="rounded-md bg-primary px-3.5 py-2.5 text-sm font-semibold text-primary-foreground shadow-sm hover:bg-primary/90"
              >
                Toggle Theme
              </button>
              <a href="#" className="text-sm font-semibold leading-6">
                Learn more <span aria-hidden="true">→</span>
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
