/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./templates/**/*.html",
    "./auth_bridge/templates/**/*.html",
    "./oidc_provider/templates/**/*.html",
    "./apps/**/templates/**/*.html",
    "./auth_bridge/static/**/*.js",
    "./static/**/*.js",
  ],
  darkMode: 'class',
  theme: {
    extend: {},
  },
  plugins: [],
};
