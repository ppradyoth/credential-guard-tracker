# Credential Guard Tracker Dashboard

Beautiful, minimalist GitHub Pages dashboard for credential-guard ecosystem tracking.

## Features

🎨 **Minimal Design**
- Apple/Google-inspired aesthetic
- Light theme with dark mode support
- Responsive design (desktop, tablet, mobile)
- Clean typography and whitespace

📊 **Real-time Metrics**
- PR status and engagement
- Repository statistics
- Related issues by keyword
- Last updated timestamp

🔄 **Auto-updated**
- Fetches live data from GitHub API
- No build step required
- Client-side rendering (instant loads)

## Access

Live dashboard: [https://ppradyoth.github.io/credential-guard-tracker](https://ppradyoth.github.io/credential-guard-tracker)

## Files

- `index.html` — Main page structure
- `style.css` — Minimalist styling (Apple/Google inspired)
- `script.js` — Data fetching and rendering logic

## How It Works

1. **No backend** — Pure static files served by GitHub Pages
2. **GitHub API** — Fetches PR, repo, and issue data client-side
3. **Responsive** — Works on all devices and screen sizes
4. **Auto-deploy** — Updates whenever `docs/` folder changes

## Design Principles

✨ **Minimalism**
- Only essential UI elements
- Lots of whitespace
- Clear visual hierarchy

🎯 **Apple-Inspired**
- System fonts (`-apple-system`)
- Subtle shadows and borders
- Smooth transitions
- Clean card-based layout

🎨 **Google-Inspired**
- Material Design principles
- Clear affordances
- Accessible color contrast
- Responsive grid system

🌓 **Dark Mode**
- Automatic detection (`prefers-color-scheme`)
- Comfortable viewing in low light
- No jarring brightness changes

## Customization

Edit `style.css` to customize colors:

```css
:root {
    --accent: #0071e3;  /* Primary color */
    --bg-primary: #ffffff;  /* Background */
    --text-primary: #1d1d1f;  /* Text */
}
```

## Browser Support

- Modern browsers (Chrome, Firefox, Safari, Edge)
- Mobile browsers (iOS Safari, Chrome Mobile)
- Dark mode support on all modern platforms

## License

Part of [credential-guard-tracker](https://github.com/ppradyoth/credential-guard-tracker)
