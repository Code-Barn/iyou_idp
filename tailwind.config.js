/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './templates/**/*.html',
    './auth_bridge/templates/**/*.html',
    './apps/**/templates/**/*.html',
    './static/**/*.js',
    './auth_bridge/static/**/*.js'
  ],
  theme: {
    extend: {
      screens: { 'xs': '360px' },
      colors: {
        onyx: { 950: '#0B0F19', 900: '#131826', 800: '#1E2538' }
      }
    }
  },
  plugins: []
}
