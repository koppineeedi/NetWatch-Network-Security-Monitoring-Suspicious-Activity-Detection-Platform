/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#07090e',
          card: '#0e131f',
          border: '#1e293b',
          accent: '#00f0ff',
          success: '#00ff9d',
          warning: '#ffb800',
          danger: '#ff0055',
          purple: '#a855f7',
          muted: '#64748b'
        }
      },
      fontFamily: {
        mono: ['Fira Code', 'Courier New', 'monospace'],
      },
      boxShadow: {
        'glow-cyan': '0 0 20px rgba(0, 240, 255, 0.25)',
        'glow-danger': '0 0 20px rgba(255, 0, 85, 0.3)',
        'glow-success': '0 0 20px rgba(0, 255, 157, 0.25)',
      }
    },
  },
  plugins: [],
}
