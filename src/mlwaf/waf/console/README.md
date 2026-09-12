# Console assets

Plain HTML, CSS and JavaScript, served by the same process as the proxy. No build
step and no framework: the surface is one table, one detail pane and a slider, and
a toolchain would cost more than it saves.

- `index.html` structure
- `style.css` the palette and layout
- `app.js` server sent events, filtering, threshold impact, feedback

Live updates arrive over `/_waf/stream`. Each console holds a bounded queue on the
server, so a browser that cannot keep up drops events instead of applying
backpressure to the request path.
