(() => {
  "use strict";

  // Everything the page shows comes from the inline JSON block. Values are
  // config data, so they only ever reach the DOM as text (textContent,
  // createTextNode, setAttribute on inert attributes), never as markup. The
  // script makes no network request and touches no storage or cookies.
  const doc = document;
  const root = doc.documentElement;
  const $ = (id) => doc.getElementById(id);
  const data = JSON.parse($("iam-data").textContent);
  const svg = $("graph");
  const NS = svg.namespaceURI;
  const viewport = $("viewport");
  const layer = { bands: $("bands"), edges: $("edges"), nodes: $("nodes"), labels: $("edge-labels") };

  const DOT = " \u00b7 ";
  const ELLIPSIS = "\u2026";
  const DASH = "\u2014";
  const CHEVRON = " \u203a ";

  // How each kind of node is drawn: column, section, categorical slot and
  // glyph. Shape and position repeat what the hue says, so identity never
  // rests on colour alone.
  const KINDS = {
    user: { col: 0, section: "Users", hue: 1, shape: "circle", title: "User" },
    external_user: { col: 0, section: "Guests", hue: 1, shape: "circle", hollow: true, title: "Guest user" },
    github_handle: { col: 0, section: "GitHub handles", hue: 1, shape: "square", hollow: true, title: "GitHub handle" },
    service_principal: { col: 0, section: "Service principals", hue: 2, shape: "hex", title: "Service principal" },
    managed_identity: { col: 0, section: "Managed identities", hue: 2, shape: "hex", hollow: true, title: "Managed identity" },
    shared_mailbox: { col: 0, section: "Shared mailboxes", hue: 2, shape: "hex", title: "Shared mailbox" },
    unresolved: { col: 0, section: "Unresolved references", hue: 0, shape: "unresolved", title: "Unresolved reference" },
    security_group: { col: 1, section: "Security groups", hue: 3, shape: "square", title: "Security group" },
    license_group: { col: 1, section: "License groups", hue: 3, shape: "square", title: "License group" },
    m365_group: { col: 1, section: "Microsoft 365 groups", hue: 3, shape: "square", title: "Microsoft 365 group" },
    mailing_list: { col: 1, section: "Mailing lists", hue: 3, shape: "square", hollow: true, title: "Mailing list" },
    policy: { col: 2, section: "Access policies", hue: 4, shape: "diamond", title: "Access policy" },
    github_team: { col: 3, section: "GitHub", hue: 5, shape: "tile", mono: "GH", title: "GitHub team" },
    linear: { col: 3, section: "Linear", hue: 5, shape: "tile", mono: "LN", title: "Linear" },
    entra_role: { col: 3, section: "Entra & Azure", hue: 5, shape: "tile", mono: "EN", title: "Entra directory role" },
    azure_rbac: { col: 3, section: "Entra & Azure", hue: 5, shape: "tile", mono: "AZ", title: "Azure RBAC role" },
    sharepoint_site: { col: 3, section: "SharePoint", hue: 5, shape: "tile", mono: "SP", title: "SharePoint site" },
    application: { col: 3, section: "Applications", hue: 6, shape: "app", title: "Application" },
    workspace: { col: 4, section: "Workspaces", hue: 6, shape: "square", hollow: true, title: "Workspace" },
  };
  const COLUMNS = ["Principals", "Groups", "Access policies", "Platforms & applications", "Workspaces"];
  const SECTIONS = COLUMNS.map((_, col) =>
    Object.values(KINDS)
      .filter((k) => k.col === col)
      .map((k) => k.section)
      .filter((s, i, all) => all.indexOf(s) === i)
  );
  const PRINCIPAL_KINDS = ["user", "external_user", "github_handle", "service_principal", "managed_identity", "shared_mailbox"];
  const GROUP_KINDS = ["security_group", "license_group", "m365_group", "mailing_list"];
  const FILTERS = [
    { id: "humans", label: "Humans", hue: 1, shape: "circle", kinds: ["user", "external_user", "github_handle"] },
    { id: "nonhuman", label: "Non-human", hue: 2, shape: "hex", kinds: ["service_principal", "managed_identity", "shared_mailbox"] },
    { id: "groups", label: "Groups", hue: 3, shape: "square", kinds: GROUP_KINDS },
    { id: "policies", label: "Access policies", hue: 4, shape: "diamond", kinds: ["policy"] },
    { id: "platforms", label: "Platforms", hue: 5, shape: "tile", kinds: ["github_team", "linear", "entra_role", "azure_rbac", "sharepoint_site"] },
    { id: "apps", label: "Applications & workspaces", hue: 6, shape: "tile", kinds: ["application", "workspace"] },
  ];
  const FILTER_OF = new Map();
  for (const f of FILTERS) for (const kind of f.kinds) FILTER_OF.set(kind, f.id);
  const TONE_ICON = { info: "i", warning: "!", critical: "\u00d7" };
  const TONE_NAME = { info: "Note", warning: "Warning", critical: "Problem" };

  // Geometry in SVG user units. Card size fits a display name and an email
  // address; the wider gap between columns 2 and 3 is the plane boundary.
  const G = { w: 232, h: 46, gapY: 10, section: 28, colGap: 92, planeGap: 150, top: 116, left: 34, pad: 18, foot: 72 };
  // Interaction tuning: a press that travels less than CLICK_SLOP pixels is
  // a click, not a pan; zoom spans a quarter of the fitted overview to
  // MAX_ZOOM times actual size; each zoom step and wheel notch scale by these.
  const CLICK_SLOP = 4;
  const MAX_ZOOM = 4;
  const ZOOM_STEP = 1.25;
  const WHEEL_RATE = 0.0015;
  const FIT_MARGIN = 24;

  const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  const push = (map, key, value) => {
    const list = map.get(key);
    if (list) list.push(value);
    else map.set(key, [value]);
  };
  const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));

  const byId = new Map(data.nodes.map((n) => [n.id, n]));
  const inAll = new Map();
  for (const e of data.edges) push(inAll, e.target, e);
  const haystack = new Map(
    data.nodes.map((n) => [
      n.id,
      [n.label, n.name, n.sub, KINDS[n.kind].title, ...n.props.map((p) => p[1]), ...n.badges.map((b) => b.text)]
        .join("\n")
        .toLowerCase(),
    ])
  );
  const label = (id) => (byId.has(id) ? byId.get(id).label : id);

  const state = {
    env: data.environments.includes(data.defaultEnvironment) ? data.defaultEnvironment : data.environments[0],
    query: "",
    hidden: new Set(),
    owners: true,
    selected: null,
    hovered: null,
    view: "graph",
    theme: "auto",
    t: { x: 0, y: 0, k: 1 },
    fitK: 1,
    userMoved: false,
    graphDirty: false,
  };
  let layout = null;
  const nodeEls = new Map();
  const edgeEls = new Map();

  // ---- DOM helpers -----------------------------------------------------

  function el(tag, attrs, text) {
    const node = doc.createElementNS(NS, tag);
    if (attrs) for (const key of Object.keys(attrs)) node.setAttribute(key, String(attrs[key]));
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function h(tag, attrs, ...children) {
    const node = doc.createElement(tag);
    if (attrs) {
      for (const key of Object.keys(attrs)) {
        if (key === "text") node.textContent = attrs[key];
        else node.setAttribute(key, attrs[key]);
      }
    }
    for (const child of children) {
      if (child) node.appendChild(typeof child === "string" ? doc.createTextNode(child) : child);
    }
    return node;
  }

  function swatch(kind) {
    const k = KINDS[kind];
    const shape = k.shape === "app" ? "tile" : k.shape === "square" && k.hollow ? "ring" : k.shape;
    return h("span", { class: `swatch hue-${k.hue} shape-${shape}`, "aria-hidden": "true" });
  }

  // ---- visibility --------------------------------------------------------

  function inEnv(node) {
    if (node.env) return node.env === state.env;
    if (node.kind === "policy") {
      const beam = (inAll.get(node.id) || []).find((e) => e.kind === "policy");
      return !beam || inEnv(byId.get(beam.source));
    }
    return true;
  }
  const shown = (node) => inEnv(node) && !state.hidden.has(FILTER_OF.get(node.kind));
  const rowShown = (row) => row.envs.every((env) => env === state.env);

  // ---- layout ------------------------------------------------------------

  function computeLayout() {
    const visible = new Set(data.nodes.filter(shown).map((n) => n.id));
    const edges = data.edges.filter(
      (e) => visible.has(e.source) && visible.has(e.target) && (e.kind !== "owner" || state.owners)
    );
    const index = { out: new Map(), in: new Map() };
    const nbrs = new Map();
    for (const e of edges) {
      push(index.out, e.source, e);
      push(index.in, e.target, e);
      push(nbrs, e.source, e.target);
      push(nbrs, e.target, e.source);
    }
    const colOf = (id) => KINDS[byId.get(id).kind].col;
    const sectionOf = (n) => SECTIONS[KINDS[n.kind].col].indexOf(KINDS[n.kind].section);
    const byName = (a, b) => cmp(a.label.toLowerCase(), b.label.toLowerCase()) || cmp(a.id, b.id);

    // A node with no edge in view sinks to the end of its section.
    const linked = (n) => (nbrs.has(n.id) ? 1 : 0);
    const rank = (a, b) => sectionOf(a) - sectionOf(b) || linked(b) - linked(a);
    const cols = COLUMNS.map(() => []);
    for (const n of data.nodes) if (visible.has(n.id)) cols[KINDS[n.kind].col].push(n);
    for (const col of cols) col.sort((a, b) => rank(a, b) || byName(a, b));

    // A column is a stack: offsets(col)[i] is how far node i sits below the
    // column's first node, section headers included.
    const offsets = (col) => {
      const off = [];
      col.forEach((n, i) => {
        off.push(i ? off[i - 1] + G.h + G.gapY + (sectionOf(n) !== sectionOf(col[i - 1]) ? G.section : 0) : 0);
      });
      return off;
    };
    const first = G.top + G.section;
    const y = new Map();
    const stack = (col) => offsets(col).forEach((o, i) => y.set(col[i].id, first + o));
    cols.forEach(stack);

    // Ordering: barycentric sweeps. Within its section each node moves
    // toward the mean height of its neighbours in other columns, until no
    // column changes order.
    const centre = (n, c) => {
      const ys = (nbrs.get(n.id) || []).filter((m) => colOf(m) !== c).map((m) => y.get(m));
      return ys.length ? ys.reduce((s, v) => s + v, 0) / ys.length : y.get(n.id);
    };
    for (let sweep = 0; sweep < data.nodes.length; sweep++) {
      let changed = false;
      for (const c of sweep % 2 ? [3, 2, 1, 0, 4] : [1, 2, 3, 4, 0]) {
        const before = cols[c].map((n) => n.id).join("\n");
        const bary = new Map(cols[c].map((n) => [n.id, centre(n, c)]));
        cols[c].sort((a, b) => rank(a, b) || bary.get(a.id) - bary.get(b.id) || byName(a, b));
        stack(cols[c]);
        if (cols[c].map((n) => n.id).join("\n") !== before) changed = true;
      }
      if (!changed) break;
    }

    // Placement: each column keeps its order and spacing and slides every
    // run of nodes as close to the mean height of their neighbours as the
    // tallest column's extent allows. For one column that is isotonic
    // regression (pool adjacent violators) of target minus offset, clamped
    // to the extent; columns are relaxed in turn until no node moves by half
    // a unit, finer than the screen can show.
    const span = Math.max(...cols.map((col) => (col.length ? offsets(col)[col.length - 1] : 0)));
    const place = (col, c) => {
      if (!col.length) return 0;
      const off = offsets(col);
      const lowest = first + span - off[off.length - 1];
      const blocks = [];
      col.forEach((n, i) => {
        let block = { start: i, count: 1, sum: centre(n, c) - off[i] };
        while (blocks.length) {
          const prev = blocks[blocks.length - 1];
          if (prev.sum / prev.count <= block.sum / block.count) break;
          blocks.pop();
          block = { start: prev.start, count: prev.count + block.count, sum: prev.sum + block.sum };
        }
        blocks.push(block);
      });
      let moved = 0;
      for (const b of blocks) {
        const z = clamp(b.sum / b.count, first, lowest);
        for (let i = b.start; i < b.start + b.count; i++) {
          moved = Math.max(moved, Math.abs(y.get(col[i].id) - (z + off[i])));
          y.set(col[i].id, z + off[i]);
        }
      }
      return moved;
    };
    for (let pass = 0; pass < data.nodes.length; pass++) {
      let moved = 0;
      for (const c of pass % 2 ? [4, 3, 2, 1, 0] : [0, 1, 2, 3, 4]) moved = Math.max(moved, place(cols[c], c));
      if (moved < 0.5) break;
    }
    // Offsets are whole units, so rounding keeps every gap intact.
    for (const [id, v] of y) y.set(id, Math.round(v));

    const xs = [];
    let x = G.left;
    for (let c = 0; c < cols.length; c++) {
      xs.push(x);
      x += G.w + (c === 1 ? G.planeGap : G.colGap);
    }
    let bottom = G.top + G.section + G.h;
    for (const id of visible) bottom = Math.max(bottom, y.get(id) + G.h);
    const pos = new Map();
    for (const col of cols) for (const n of col) pos.set(n.id, { x: xs[KINDS[n.kind].col], y: y.get(n.id) });
    return {
      visible,
      edges,
      index,
      cols,
      xs,
      pos,
      sectionOf,
      bottom,
      width: xs[xs.length - 1] + G.w + G.left,
      height: bottom + G.foot,
    };
  }

  // ---- drawing -------------------------------------------------------------

  function hexPath(cx, cy, r) {
    const pts = [];
    for (let i = 0; i < 6; i++) {
      const a = (Math.PI / 3) * i;
      pts.push(`${(cx + r * Math.cos(a)).toFixed(2)},${(cy + r * Math.sin(a)).toFixed(2)}`);
    }
    return `M${pts.join("L")}Z`;
  }

  function glyph(k, cx, cy) {
    const cls = `glyph hue-${k.hue}${k.hollow ? " hollow" : ""}`;
    const g = el("g", { "aria-hidden": "true" });
    if (k.shape === "circle") {
      g.append(el("circle", { class: cls, cx, cy, r: k.hollow ? 8 : 9 }));
    } else if (k.shape === "square") {
      g.append(el("rect", { class: cls, x: cx - 9, y: cy - 9, width: 18, height: 18, rx: 4.5 }));
    } else if (k.shape === "hex") {
      g.append(el("path", { class: cls, d: hexPath(cx, cy, k.hollow ? 9 : 10) }));
    } else if (k.shape === "diamond") {
      g.append(el("path", { class: cls, d: `M${cx},${cy - 11}L${cx + 11},${cy}L${cx},${cy + 11}L${cx - 11},${cy}Z` }));
    } else if (k.shape === "tile") {
      g.append(el("rect", { class: cls, x: cx - 11, y: cy - 10, width: 22, height: 20, rx: 5 }));
      g.append(el("text", { class: "glyph-text", x: cx, y: cy + 0.5 }, k.mono));
    } else if (k.shape === "app") {
      g.append(el("rect", { class: cls, x: cx - 11, y: cy - 10, width: 22, height: 20, rx: 5 }));
      g.append(el("rect", { class: "glyph-bar", x: cx - 7, y: cy - 5.5, width: 14, height: 2.5, rx: 1.25 }));
      g.append(el("rect", { class: "glyph-bar", x: cx - 7, y: cy - 0.5, width: 9, height: 2.5, rx: 1.25 }));
    } else {
      g.append(el("circle", { class: "glyph unresolved", cx, cy, r: 8.5 }));
    }
    return g;
  }

  const worstTone = (n) =>
    n.badges.some((b) => b.tone === "critical") ? "critical" : n.badges.some((b) => b.tone === "warning") ? "warning" : null;

  function measure(text) {
    // A hidden document reports zero lengths; estimate from the character
    // count then, so a card is never left overflowing.
    return text.getComputedTextLength() || text.textContent.length * 6.6;
  }

  function fit(text, room) {
    const full = text.textContent;
    if (!full || measure(text) <= room) return;
    let lo = 0;
    let hi = full.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      text.textContent = full.slice(0, mid) + ELLIPSIS;
      if (measure(text) <= room) lo = mid;
      else hi = mid - 1;
    }
    text.textContent = full.slice(0, lo) + ELLIPSIS;
  }

  function ariaLabel(n) {
    const parts = [`${KINDS[n.kind].title}: ${n.label}`];
    if (n.sub) parts.push(n.sub);
    if (n.agent) parts.push("agent group");
    const tone = worstTone(n);
    if (tone) parts.push(TONE_NAME[tone].toLowerCase() + ": " + n.badges.find((b) => b.tone === tone).text);
    return parts.join(", ");
  }

  function drawNode(n) {
    const k = KINDS[n.kind];
    const p = layout.pos.get(n.id);
    const g = el("g", {
      class: `node kind-${n.kind}`,
      transform: `translate(${p.x},${p.y})`,
      tabindex: 0,
      role: "button",
      "data-id": n.id,
      "aria-label": ariaLabel(n),
    });
    g.append(el("rect", { class: "card", width: G.w, height: G.h, rx: 9 }));
    g.append(glyph(k, 22, G.h / 2));
    const title = el("text", { class: "label", x: 42, y: 19 }, n.label);
    const sub = el("text", { class: "sub", x: 42, y: 34 }, n.sub);
    g.append(title, sub);
    if (n.agent) g.append(el("path", { class: "agent-mark", d: hexPath(31, G.h / 2 + 8, 6) }));
    const tone = worstTone(n);
    if (tone) {
      const mark = el("g", { class: `status-mark ${tone}`, transform: `translate(${G.w - 13},13)`, "aria-hidden": "true" });
      mark.append(el("circle", { r: 7 }), el("text", { x: 0, y: 0.5 }, "!"));
      g.append(mark);
    }
    layer.nodes.append(g);
    nodeEls.set(n.id, g);
    const room = G.w - 42 - (tone ? 26 : 12);
    fit(title, room);
    fit(sub, room);
  }

  function edgeGeometry(e) {
    const a = layout.pos.get(e.source);
    const b = layout.pos.get(e.target);
    const offset = e.kind === "owner" ? 7 : 0;
    const y1 = a.y + G.h / 2 + offset;
    const y2 = b.y + G.h / 2 + offset;
    if (a.x === b.x) {
      // Nested groups share a column: loop out to its right and back in.
      const x0 = a.x + G.w;
      const bulge = 40;
      return { p0: [x0, y1], p1: [x0 + bulge, y1], p2: [x0 + bulge, y2], p3: [x0, y2] };
    }
    const x1 = a.x + G.w;
    const x2 = b.x;
    const dx = Math.max(32, (x2 - x1) / 2);
    return { p0: [x1, y1], p1: [x1 + dx, y1], p2: [x2 - dx, y2], p3: [x2, y2] };
  }

  function drawEdge(e) {
    const { p0, p1, p2, p3 } = edgeGeometry(e);
    const path = el("path", {
      class: `edge ${e.kind}`,
      d: `M${p0[0]},${p0[1]}C${p1[0]},${p1[1]} ${p2[0]},${p2[1]} ${p3[0]},${p3[1]}`,
      "data-id": e.id,
    });
    layer.edges.append(path);
    edgeEls.set(e.id, path);
  }

  function drawBands() {
    const L = layout;
    const bandTop = G.top - 78;
    const bandBottom = L.bottom + G.pad;
    const planes = [
      { cls: "band plane-1", x0: L.xs[0], x1: L.xs[1] + G.w, title: "PLANE 1 \u00b7 IDENTITY & DIRECTORY" },
      { cls: "band plane-2", x0: L.xs[2], x1: L.xs[4] + G.w, title: "PLANE 2 \u00b7 ACCESS & APPLICATION SURFACES" },
    ];
    for (const p of planes) {
      layer.bands.append(
        el("rect", { class: p.cls, x: p.x0 - G.pad, y: bandTop, width: p.x1 - p.x0 + 2 * G.pad, height: bandBottom - bandTop, rx: 16 }),
        el("text", { class: "band-title", x: p.x0, y: bandTop + 26 }, p.title)
      );
    }
    const hx = (L.xs[1] + G.w + L.xs[2]) / 2;
    const mid = (bandTop + bandBottom) / 2;
    layer.bands.append(
      el("line", { class: "handoff-line", x1: hx - 10, y1: bandTop + 12, x2: hx - 10, y2: bandBottom - 12 }),
      el(
        "text",
        { class: "handoff-text", x: 0, y: 0, "text-anchor": "middle", transform: `translate(${hx + 8},${mid}) rotate(-90)` },
        "handoff: SecurityGroup \u2192 resolved_name / Entra object id"
      )
    );
    L.cols.forEach((col, c) => {
      const x = L.xs[c];
      layer.bands.append(
        el("text", { class: "col-title", x, y: G.top - 24 }, COLUMNS[c]),
        el("text", { class: "col-count", x: x + G.w, y: G.top - 24, "text-anchor": "end" }, String(col.length))
      );
      if (!col.length) layer.bands.append(el("text", { class: "empty-col", x, y: G.top + G.section + 16 }, "none in view"));
      let section = -1;
      for (const n of col) {
        if (L.sectionOf(n) === section) continue;
        section = L.sectionOf(n);
        layer.bands.append(el("text", { class: "section-title", x, y: L.pos.get(n.id).y - 9 }, KINDS[n.kind].section.toUpperCase()));
      }
    });
  }

  function render() {
    layout = computeLayout();
    for (const g of Object.values(layer)) g.replaceChildren();
    nodeEls.clear();
    edgeEls.clear();
    drawBands();
    for (const e of layout.edges) drawEdge(e);
    for (const n of data.nodes) if (layout.visible.has(n.id)) drawNode(n);
    if (state.hovered && !layout.visible.has(state.hovered)) state.hovered = null;
    if (state.selected && !layout.visible.has(state.selected)) state.selected = null;
    if (state.selected) openPanel(byId.get(state.selected));
    else $("panel").hidden = true;
    state.graphDirty = false;
    root.setAttribute("data-rendered-nodes", String(nodeEls.size));
    root.setAttribute("data-rendered-edges", String(edgeEls.size));
    applyFocus();
  }

  // ---- tracing -------------------------------------------------------------

  // What the node reaches (downstream) and who reaches it (upstream). Grant
  // edges into an application carry the workspaces they open, so a trace
  // through an application follows only those workspaces.
  function trace(id) {
    const nodes = new Set([id]);
    const edges = new Set();
    const { out, in: inc } = layout.index;

    const down = [[id, null]];
    const seenDown = new Set();
    while (down.length) {
      const [nid, scope] = down.pop();
      const key = `${nid}|${scope ? scope.join(",") : "*"}`;
      if (seenDown.has(key)) continue;
      seenDown.add(key);
      for (const e of out.get(nid) || []) {
        if (e.kind === "owner") continue;
        if (e.kind === "workspace" && scope && !scope.includes(e.workspace)) continue;
        edges.add(e.id);
        nodes.add(e.target);
        down.push([e.target, e.kind === "grant" && e.workspaces ? e.workspaces : null]);
      }
    }

    const up = [[id, null]];
    const seenUp = new Set();
    while (up.length) {
      const [nid, ws] = up.pop();
      const key = `${nid}|${ws || "*"}`;
      if (seenUp.has(key)) continue;
      seenUp.add(key);
      for (const e of inc.get(nid) || []) {
        if (e.kind === "owner") continue;
        if (e.kind === "grant" && ws && !(e.workspaces || []).includes(ws)) continue;
        edges.add(e.id);
        nodes.add(e.source);
        up.push([e.source, e.kind === "workspace" ? e.workspace : null]);
      }
    }

    // Owners of the focused group, or the groups the focused principal owns.
    for (const e of [...(out.get(id) || []), ...(inc.get(id) || [])]) {
      if (e.kind !== "owner") continue;
      edges.add(e.id);
      nodes.add(e.source);
      nodes.add(e.target);
    }
    return { nodes, edges };
  }

  function matchSet() {
    const hits = new Set();
    for (const id of layout.visible) if (haystack.get(id).includes(state.query)) hits.add(id);
    return hits;
  }

  function grantText(e) {
    let text = e.label || "";
    if (e.workspaces && e.workspaces.length) text += DOT + e.workspaces.join(", ");
    if (e.scopes && e.scopes.length) text += DOT + e.scopes.join(" ");
    return text;
  }

  function bezierAt(e, s) {
    const { p0, p1, p2, p3 } = edgeGeometry(e);
    const u = 1 - s;
    const w = [u * u * u, 3 * u * u * s, 3 * u * s * s, s * s * s];
    return [0, 1].map((i) => w[0] * p0[i] + w[1] * p1[i] + w[2] * p2[i] + w[3] * p3[i]);
  }

  // Where along its curve a label may sit, middle first. A label that
  // collides with one already placed at every stop is left off: the side
  // panel and the table carry every grant in full.
  const LABEL_STOPS = [0.5, 0.38, 0.62, 0.26, 0.74];

  function drawEdgeLabels(hot) {
    layer.labels.replaceChildren();
    if (!hot) return;
    const placed = [];
    const clear = (r) => !placed.some((o) => r.x < o.x + o.w && o.x < r.x + r.w && r.y < o.y + o.h && o.y < r.y + r.h);
    for (const e of layout.edges) {
      if (!hot.has(e.id) || (e.kind !== "grant" && e.kind !== "rbac")) continue;
      const g = el("g", { class: "edge-label" });
      const text = el("text", { x: 0, y: 0, "text-anchor": "middle" }, grantText(e));
      g.append(text);
      layer.labels.append(g);
      const b = text.getBBox();
      const box = { x: b.x - 6, y: b.y - 2, w: b.width + 12, h: b.height + 4 };
      const spot = LABEL_STOPS.map((s) => bezierAt(e, s)).find(([mx, my]) => clear({ ...box, x: mx + box.x, y: my + box.y }));
      if (!spot) {
        g.remove();
        continue;
      }
      placed.push({ ...box, x: spot[0] + box.x, y: spot[1] + box.y });
      g.setAttribute("transform", `translate(${spot[0].toFixed(1)},${spot[1].toFixed(1)})`);
      g.insertBefore(el("rect", { x: box.x, y: box.y, width: box.w, height: box.h, rx: 6 }), text);
    }
  }

  function applyFocus() {
    if (!layout) return;
    const focus = state.hovered || state.selected;
    const t = focus && layout.visible.has(focus) ? trace(focus) : null;
    const matches = state.query ? matchSet() : null;
    for (const [id, g] of nodeEls) {
      g.classList.toggle("dim", t ? !t.nodes.has(id) : matches ? !matches.has(id) : false);
      g.classList.toggle("selected", id === state.selected);
      g.classList.toggle("focus", id === focus);
      g.classList.toggle("match", !!matches && matches.has(id));
    }
    for (const e of layout.edges) {
      const path = edgeEls.get(e.id);
      const hot = !!t && t.edges.has(e.id);
      path.classList.toggle("hot", hot);
      path.classList.toggle("dim", t ? !hot : matches ? !(matches.has(e.source) && matches.has(e.target)) : false);
      if (hot) layer.edges.append(path);
    }
    // Labels are measured, so they wait until the graph is on screen.
    drawEdgeLabels(t && state.view === "graph" ? t.edges : null);
    $("search-count").textContent = matches ? `${matches.size} match${matches.size === 1 ? "" : "es"}` : "";
  }

  // ---- side panel ----------------------------------------------------------

  function viaText(row) {
    return row.via.length ? "via " + row.via.map(label).join(CHEVRON) : "direct";
  }

  function rowGrant(row) {
    let text = row.grant;
    if (row.workspaces.length) text += DOT + row.workspaces.join(", ");
    if (row.scopes.length) text += DOT + row.scopes.join(" ");
    return text;
  }

  function principalsReaching(n) {
    const items = [];
    const seen = new Set();
    for (const row of data.rows) {
      if (!rowShown(row)) continue;
      const hit = n.kind === "workspace" ? row.workspaces.includes(n.name) : row.target === n.id;
      if (!hit) continue;
      const note = (n.kind === "workspace" ? label(row.target) + DOT + row.grant : rowGrant(row)) + DOT + viaText(row);
      const key = `${row.principal}|${note}`;
      if (seen.has(key)) continue;
      seen.add(key);
      items.push({ id: row.principal, note });
    }
    return items;
  }

  function relations(n) {
    const out = layout.index.out.get(n.id) || [];
    const inc = layout.index.in.get(n.id) || [];
    const of = (list, kind) => list.filter((e) => e.kind === kind);
    const sections = [];
    const add = (title, items) => {
      if (items.length) sections.push({ title, items });
    };
    const col = KINDS[n.kind].col;
    if (col === 0) {
      add("Member of", of(out, "member").map((e) => ({ id: e.target })));
      add("Owner of", of(out, "owner").map((e) => ({ id: e.target })));
      add("GitHub access as an external member", of(out, "external_member").map((e) => ({ id: e.target, note: e.label })));
      add("Azure RBAC", of(out, "rbac").map((e) => ({ id: e.target, note: e.label })));
      add(
        "Effective access",
        data.rows
          .filter((r) => r.principal === n.id && rowShown(r))
          .map((r) => ({ id: r.target, note: rowGrant(r) + DOT + viaText(r) + (r.policy ? DOT + label(r.policy) : "") }))
      );
    } else if (col === 1) {
      add("Members", of(inc, "member").map((e) => ({ id: e.source })));
      add("Owners", of(inc, "owner").map((e) => ({ id: e.source })));
      add("Nested in", of(out, "member").map((e) => ({ id: e.target })));
      add("Access policies", of(out, "policy").map((e) => ({ id: e.target })));
      add(
        "Grants through its policies",
        of(out, "policy").flatMap((beam) =>
          of(layout.index.out.get(beam.target) || [], "grant").map((e) => ({
            id: e.target,
            note: grantText(e) + DOT + "via " + label(beam.target),
          }))
        )
      );
      add("Azure RBAC", of(out, "rbac").map((e) => ({ id: e.target, note: e.label })));
    } else if (n.kind === "policy") {
      add("Held by", of(inc, "policy").map((e) => ({ id: e.source })));
      add("External GitHub members", of(inc, "external_member").map((e) => ({ id: e.source })));
      add("Grants", of(out, "grant").map((e) => ({ id: e.target, note: grantText(e) })));
    } else if (n.kind === "workspace") {
      const declaring = of(inc, "workspace");
      add("Declared by", declaring.map((e) => ({ id: e.source })));
      const opened = [];
      for (const w of declaring) {
        for (const g of of(layout.index.in.get(w.source) || [], "grant")) {
          if (!(g.workspaces || []).includes(n.name)) continue;
          opened.push({ id: g.source, note: label(w.source) + DOT + g.role + (g.scopes.length ? DOT + g.scopes.join(" ") : "") });
        }
      }
      add("Opened by", opened);
      add("Principals reaching it", principalsReaching(n));
    } else {
      add("Granted by", of(inc, "grant").map((e) => ({ id: e.source, note: grantText(e) })));
      add("Held by (Azure RBAC)", of(inc, "rbac").map((e) => ({ id: e.source, note: e.label })));
      add("Workspaces", of(out, "workspace").map((e) => ({ id: e.target })));
      add("Principals reaching it", principalsReaching(n));
    }
    return sections;
  }

  function relationList(section) {
    const list = h("ul");
    for (const item of section.items) {
      const target = byId.get(item.id);
      const button = h(
        "button",
        { type: "button" },
        swatch(target.kind),
        h("span", { class: "item-main" }, h("span", { class: "item-label", text: target.label }), item.note ? h("span", { class: "item-note", text: item.note }) : null)
      );
      button.addEventListener("click", () => select(item.id, { reveal: true }));
      list.append(h("li", null, button));
    }
    return h("section", { class: "rel" }, h("h3", { text: section.title }), list);
  }

  function openPanel(n) {
    const k = KINDS[n.kind];
    $("panel-kind").replaceChildren(swatch(n.kind), doc.createTextNode(k.title + (n.agent ? DOT + "agent group" : "") + (n.env ? DOT + n.env.toUpperCase() : "")));
    $("panel-title").textContent = n.label;
    $("panel-sub").textContent = n.sub;
    const body = $("panel-body");
    body.replaceChildren();
    if (n.badges.length) {
      body.append(
        h(
          "div",
          { class: "badges" },
          ...n.badges.map((b) =>
            h(
              "div",
              { class: `badge ${b.tone}` },
              h("span", { class: "icon", "aria-hidden": "true", text: TONE_ICON[b.tone] }),
              h("span", null, h("span", { class: "visually-hidden", text: TONE_NAME[b.tone] + ": " }), b.text)
            )
          )
        )
      );
    }
    if (n.props.length) {
      const dl = h("dl", { class: "props" });
      for (const [key, value] of n.props) dl.append(h("dt", { text: key }), h("dd", { text: value }));
      body.append(dl);
    }
    for (const section of relations(n)) body.append(relationList(section));
    $("panel").hidden = false;
  }

  function select(id, opts) {
    if (id && layout && !layout.visible.has(id)) {
      const n = byId.get(id);
      const filter = FILTER_OF.get(n.kind);
      if (!inEnv(n)) return;
      if (filter && state.hidden.has(filter)) {
        state.hidden.delete(filter);
        syncChips();
      }
      state.selected = id;
      refresh({ refit: false });
    }
    state.selected = id;
    if (id) openPanel(byId.get(id));
    else $("panel").hidden = true;
    applyFocus();
    if (id && opts && opts.reveal) reveal(id);
  }

  // ---- table view ----------------------------------------------------------

  function nodeCell(id) {
    const n = byId.get(id);
    const link = h("button", { type: "button", class: "link", text: n.label });
    link.addEventListener("click", () => {
      setView("graph");
      select(id, { reveal: true });
    });
    return h("td", null, link, h("span", { class: "cell-sub", text: KINDS[n.kind].title }));
  }

  function renderTable() {
    const body = $("table-body");
    body.replaceChildren();
    let count = 0;
    for (const row of data.rows) {
      if (!rowShown(row)) continue;
      if (state.query) {
        const text = [row.principal, row.target, row.policy, ...row.via]
          .filter(Boolean)
          .map((id) => haystack.get(id) || "")
          .concat([row.grant, ...row.workspaces, ...row.scopes].map((s) => s.toLowerCase()))
          .join("\n");
        if (!text.includes(state.query)) continue;
      }
      count++;
      const via = h("td");
      if (row.via.length) {
        row.via.forEach((id, i) => {
          if (i) via.append(doc.createTextNode(CHEVRON));
          const link = h("button", { type: "button", class: "link", text: label(id) });
          link.addEventListener("click", () => {
            setView("graph");
            select(id, { reveal: true });
          });
          via.append(link);
        });
      } else {
        via.textContent = "direct";
      }
      body.append(
        h(
          "tr",
          null,
          nodeCell(row.principal),
          via,
          row.policy ? nodeCell(row.policy) : h("td", { text: DASH }),
          nodeCell(row.target),
          h("td", { text: row.grant }),
          h("td", { text: row.workspaces.join(", ") || DASH }),
          h("td", { text: row.scopes.join(", ") || DASH })
        )
      );
    }
    $("table-empty").hidden = count > 0;
    $("table-caption").textContent =
      `Effective access in ${state.env.toUpperCase()}: ${count} grant${count === 1 ? "" : "s"}. ` +
      "Each row is one grant a principal holds and the group and policy it flows through. " +
      "GitHub rows follow the GitHub exporter (direct members with a handle, plus external handles); " +
      "Linear rows follow the Linear executor (declared group memberships). " +
      "Disabled accounts hold no rows: they sign in to nothing.";
  }

  // ---- status bar, chips, view, theme ---------------------------------------

  function renderStatus() {
    const count = (kinds) => data.nodes.filter((n) => kinds.includes(n.kind) && inEnv(n)).length;
    const parts = [
      ["environment", state.env.toUpperCase()],
      ["principals", count(PRINCIPAL_KINDS)],
      ["groups", count(GROUP_KINDS)],
      ["access policies", count(["policy"])],
      ["applications", count(["application"])],
      ["workspaces", count(["workspace"])],
      ["grants", data.rows.filter(rowShown).length],
    ];
    const bar = $("statusbar");
    bar.replaceChildren();
    for (const [name, value] of parts) {
      bar.append(
        h("span", null, ...(name === "environment" ? ["Environment ", h("strong", { text: String(value) })] : [h("strong", { text: String(value) }), " " + name]))
      );
    }
    bar.append(h("span", { text: "read-only view \u00b7 generated by iamkit" }));
  }

  function syncChips() {
    for (const chip of $("filters").querySelectorAll(".chip[data-filter]")) {
      chip.setAttribute("aria-pressed", String(!state.hidden.has(chip.dataset.filter)));
    }
  }

  function buildFilters() {
    const box = $("filters");
    for (const f of FILTERS) {
      const count = data.nodes.filter((n) => FILTER_OF.get(n.kind) === f.id).length;
      if (!count) continue;
      const chip = h(
        "button",
        { type: "button", class: "chip", "aria-pressed": "true", "data-filter": f.id },
        h("span", { class: `swatch hue-${f.hue} shape-${f.shape}`, "aria-hidden": "true" }),
        h("span", { text: f.label }),
        h("span", { class: "count", text: String(count) })
      );
      chip.addEventListener("click", () => {
        if (state.hidden.has(f.id)) state.hidden.delete(f.id);
        else state.hidden.add(f.id);
        syncChips();
        refresh({ refit: true });
      });
      box.append(chip);
    }
    if (data.edges.some((e) => e.kind === "owner")) {
      const chip = h("button", { type: "button", class: "chip", "aria-pressed": "true" }, h("span", { text: "Ownership edges" }));
      chip.addEventListener("click", () => {
        state.owners = !state.owners;
        chip.setAttribute("aria-pressed", String(state.owners));
        refresh({ refit: false });
      });
      box.append(chip);
    }
    if (data.nodes.some((n) => n.agent)) {
      box.append(
        h(
          "span",
          { class: "chip note", title: "A security group whose members are all non-human, answered for by its human owners" },
          h("span", { class: "swatch hue-2 shape-hex", "aria-hidden": "true" }),
          h("span", { text: "marks an agent group" })
        )
      );
    }
  }

  function refresh(opts) {
    if (state.view === "graph") {
      render();
      if (opts && opts.refit) {
        state.userMoved = false;
        fitView();
      }
    } else {
      state.graphDirty = true;
    }
    renderTable();
    renderStatus();
  }

  function setView(view) {
    state.view = view;
    for (const b of $("view-toggle").querySelectorAll(".seg")) b.setAttribute("aria-pressed", String(b.dataset.view === view));
    $("graph-view").hidden = view !== "graph";
    $("table-view").hidden = view !== "table";
    hideTooltip();
    if (view !== "graph") return;
    if (state.graphDirty) {
      render();
      fitView();
    } else {
      applyFocus();
    }
  }

  function setEnv(env) {
    state.env = env;
    for (const b of $("env-toggle").querySelectorAll(".seg")) b.setAttribute("aria-pressed", String(b.dataset.env === env));
    refresh({ refit: true });
  }

  const THEMES = ["auto", "light", "dark"];
  const THEME_ICON = { auto: "\u25d0", light: "\u2600", dark: "\u263e" };

  function cycleTheme() {
    state.theme = THEMES[(THEMES.indexOf(state.theme) + 1) % THEMES.length];
    if (state.theme === "auto") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", state.theme);
    const button = $("theme-toggle");
    const text = "Colour theme: " + (state.theme === "auto" ? "automatic" : state.theme);
    button.setAttribute("aria-label", text);
    button.title = text;
    button.textContent = THEME_ICON[state.theme];
  }

  // ---- pan and zoom --------------------------------------------------------

  function setTransform(t) {
    state.t = t;
    viewport.setAttribute("transform", `translate(${t.x.toFixed(2)},${t.y.toFixed(2)}) scale(${t.k.toFixed(4)})`);
  }

  function fitView() {
    const r = svg.getBoundingClientRect();
    if (!r.width || !r.height || !layout) return;
    const k = Math.min(1, (r.width - 2 * FIT_MARGIN) / layout.width, (r.height - 2 * FIT_MARGIN) / layout.height);
    state.fitK = k;
    setTransform({ k, x: (r.width - layout.width * k) / 2, y: Math.max(FIT_MARGIN, (r.height - layout.height * k) / 2) });
  }

  function zoomAt(px, py, factor) {
    const t = state.t;
    const k = clamp(t.k * factor, state.fitK / 4, MAX_ZOOM);
    const f = k / t.k;
    setTransform({ k, x: px - (px - t.x) * f, y: py - (py - t.y) * f });
    state.userMoved = true;
  }

  function zoomBy(factor) {
    const r = svg.getBoundingClientRect();
    zoomAt(r.width / 2, r.height / 2, factor);
  }

  function reveal(id) {
    const p = layout.pos.get(id);
    if (!p) return;
    const r = svg.getBoundingClientRect();
    const { x, y, k } = state.t;
    const sx = x + (p.x + G.w / 2) * k;
    const sy = y + (p.y + G.h / 2) * k;
    if (sx >= 0 && sy >= 0 && sx <= r.width && sy <= r.height) return;
    setTransform({ k, x: r.width / 2 - (p.x + G.w / 2) * k, y: r.height / 2 - (p.y + G.h / 2) * k });
    state.userMoved = true;
  }

  const pointers = new Map();
  let gesture = null;

  svg.addEventListener("pointerdown", (ev) => {
    if (ev.pointerType === "mouse" && ev.button !== 0) return;
    pointers.set(ev.pointerId, [ev.clientX, ev.clientY]);
    svg.setPointerCapture(ev.pointerId);
    const nodeEl = ev.target.closest(".node");
    if (pointers.size === 1) {
      gesture = { kind: "press", node: nodeEl ? nodeEl.dataset.id : null, x: ev.clientX, y: ev.clientY, t: { ...state.t } };
    } else if (pointers.size === 2) {
      const [[ax, ay], [bx, by]] = [...pointers.values()];
      const r = svg.getBoundingClientRect();
      gesture = { kind: "pinch", d: Math.hypot(bx - ax, by - ay) || 1, mx: (ax + bx) / 2 - r.left, my: (ay + by) / 2 - r.top, t: { ...state.t } };
    }
  });

  svg.addEventListener("pointermove", (ev) => {
    if (!pointers.has(ev.pointerId) || !gesture) return;
    pointers.set(ev.pointerId, [ev.clientX, ev.clientY]);
    if (gesture.kind === "pinch" && pointers.size === 2) {
      const [[ax, ay], [bx, by]] = [...pointers.values()];
      const k = clamp(gesture.t.k * (Math.hypot(bx - ax, by - ay) / gesture.d), state.fitK / 4, MAX_ZOOM);
      const f = k / gesture.t.k;
      setTransform({ k, x: gesture.mx - (gesture.mx - gesture.t.x) * f, y: gesture.my - (gesture.my - gesture.t.y) * f });
      state.userMoved = true;
      return;
    }
    const dx = ev.clientX - gesture.x;
    const dy = ev.clientY - gesture.y;
    if (gesture.kind === "press" && Math.hypot(dx, dy) < CLICK_SLOP) return;
    if (gesture.kind === "press") {
      gesture.kind = "pan";
      svg.classList.add("panning");
      hideTooltip();
    }
    if (gesture.kind === "pan") {
      setTransform({ k: gesture.t.k, x: gesture.t.x + dx, y: gesture.t.y + dy });
      state.userMoved = true;
    }
  });

  function endPointer(ev) {
    if (!pointers.has(ev.pointerId)) return;
    pointers.delete(ev.pointerId);
    const g = gesture;
    if (pointers.size) return;
    gesture = null;
    svg.classList.remove("panning");
    if (ev.type !== "pointerup" || !g || g.kind !== "press") return;
    if (g.node) select(g.node === state.selected ? null : g.node);
    else select(null);
  }
  svg.addEventListener("pointerup", endPointer);
  svg.addEventListener("pointercancel", endPointer);

  svg.addEventListener(
    "wheel",
    (ev) => {
      ev.preventDefault();
      const r = svg.getBoundingClientRect();
      const unit = ev.deltaMode === 1 ? 16 : ev.deltaMode === 2 ? r.height : 1;
      zoomAt(ev.clientX - r.left, ev.clientY - r.top, Math.exp(-ev.deltaY * unit * WHEEL_RATE));
    },
    { passive: false }
  );

  // ---- hover, focus, tooltip ---------------------------------------------

  const tip = $("tooltip");

  function hideTooltip() {
    tip.hidden = true;
  }

  function placeTooltip(clientX, clientY) {
    const host = $("graph-view").getBoundingClientRect();
    let x = clientX - host.left + 14;
    let y = clientY - host.top + 14;
    if (x + tip.offsetWidth > host.width - 8) x = clientX - host.left - tip.offsetWidth - 14;
    if (y + tip.offsetHeight > host.height - 8) y = clientY - host.top - tip.offsetHeight - 14;
    tip.style.transform = `translate(${Math.max(8, x)}px, ${Math.max(8, y)}px)`;
  }

  function showTooltip(id, clientX, clientY) {
    const n = byId.get(id);
    const tone = worstTone(n);
    tip.replaceChildren(
      ...[
        h("div", { class: "tt-kind", text: KINDS[n.kind].title + (n.agent ? DOT + "agent group" : "") + (n.env ? DOT + n.env.toUpperCase() : "") }),
        h("div", { class: "tt-label", text: n.label }),
        n.sub ? h("div", { class: "tt-sub", text: n.sub }) : null,
        tone ? h("div", { class: "tt-note", text: n.badges.find((b) => b.tone === tone).text }) : null,
      ].filter(Boolean)
    );
    tip.hidden = false;
    placeTooltip(clientX, clientY);
  }

  layer.nodes.addEventListener("pointerover", (ev) => {
    const g = ev.target.closest(".node");
    if (!g || gesture) return;
    if (state.hovered !== g.dataset.id) {
      state.hovered = g.dataset.id;
      applyFocus();
    }
    showTooltip(g.dataset.id, ev.clientX, ev.clientY);
  });
  layer.nodes.addEventListener("pointermove", (ev) => {
    if (!tip.hidden) placeTooltip(ev.clientX, ev.clientY);
  });
  layer.nodes.addEventListener("pointerout", (ev) => {
    const g = ev.target.closest(".node");
    if (!g || (ev.relatedTarget && g.contains(ev.relatedTarget))) return;
    state.hovered = null;
    hideTooltip();
    applyFocus();
  });
  layer.nodes.addEventListener("focusin", (ev) => {
    const g = ev.target.closest(".node");
    if (!g) return;
    state.hovered = g.dataset.id;
    applyFocus();
    const r = g.getBoundingClientRect();
    showTooltip(g.dataset.id, r.left, r.bottom);
  });
  layer.nodes.addEventListener("focusout", () => {
    state.hovered = null;
    hideTooltip();
    applyFocus();
  });
  layer.nodes.addEventListener("keydown", (ev) => {
    const g = ev.target.closest(".node");
    if (!g || (ev.key !== "Enter" && ev.key !== " ")) return;
    ev.preventDefault();
    select(g.dataset.id === state.selected ? null : g.dataset.id);
  });

  // ---- controls ------------------------------------------------------------

  const search = $("search");
  search.addEventListener("input", () => {
    state.query = search.value.trim().toLowerCase();
    applyFocus();
    renderTable();
  });
  search.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" && state.query) {
      const hits = matchSet();
      const first = layout.cols.flat().find((n) => hits.has(n.id));
      if (first) {
        setView("graph");
        select(first.id, { reveal: true });
      }
    } else if (ev.key === "Escape") {
      ev.stopPropagation();
      search.value = "";
      state.query = "";
      applyFocus();
      renderTable();
      search.blur();
    }
  });

  doc.addEventListener("keydown", (ev) => {
    const typing = ev.target instanceof HTMLInputElement;
    if (ev.key === "/" && !typing) {
      ev.preventDefault();
      search.focus();
      search.select();
    } else if (ev.key === "Escape") {
      state.hovered = null;
      hideTooltip();
      select(null);
    } else if (!typing && state.view === "graph") {
      if (ev.key === "+" || ev.key === "=") zoomBy(ZOOM_STEP);
      else if (ev.key === "-" || ev.key === "_") zoomBy(1 / ZOOM_STEP);
      else if (ev.key === "0") {
        state.userMoved = false;
        fitView();
      }
    }
  });

  for (const b of $("env-toggle").querySelectorAll(".seg")) b.addEventListener("click", () => setEnv(b.dataset.env));
  for (const b of $("view-toggle").querySelectorAll(".seg")) b.addEventListener("click", () => setView(b.dataset.view));
  for (const b of doc.querySelectorAll("[data-zoom]")) {
    b.addEventListener("click", () => {
      if (b.dataset.zoom === "fit") {
        state.userMoved = false;
        fitView();
      } else {
        zoomBy(b.dataset.zoom === "in" ? ZOOM_STEP : 1 / ZOOM_STEP);
      }
    });
  }
  $("theme-toggle").addEventListener("click", cycleTheme);
  $("panel-close").addEventListener("click", () => select(null));
  new ResizeObserver(() => {
    if (!state.userMoved && state.view === "graph") fitView();
  }).observe(svg);

  // ---- start -----------------------------------------------------------------

  buildFilters();
  for (const b of $("env-toggle").querySelectorAll(".seg")) b.setAttribute("aria-pressed", String(b.dataset.env === state.env));
  render();
  fitView();
  renderTable();
  renderStatus();
  root.setAttribute("data-ready", "true");
})();
