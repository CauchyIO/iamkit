# Access explorer

`iam_explorer.html` is the ACME platform showcase
(`examples/acme/platform.py`) rendered by
`iamkit.export.generate_visualizer_html`. Open it in a browser; it needs no
server, build step or network.

Regenerate it after changing the showcase config or the explorer assets:

```sh
uv run python -m examples.acme.visualize
```

`tests/test_applications_and_visualizer.py` fails when the committed file
drifts from what the generator produces.

What it shows:

- **Plane 1, identity and directory**: users, guests, GitHub handles outside
  the directory, service principals, managed identities and shared mailboxes,
  and the groups that hold them, with ownership edges. A security group whose
  members are all non-human is marked as an agent group.
- **Plane 2, access and application surfaces**: each access policy's beam from
  its group onto GitHub teams, Linear, Entra directory roles, Azure RBAC,
  SharePoint sites and declared applications, and on to the workspaces each
  binding opens.

Controls: the DEV/ACC/PRD toggle shows the groups of one environment, the
search box and kind chips narrow the graph, clicking a node traces what it
reaches and who reaches it and opens its details, and the Table view lists
every effective grant with the group path and policy it flows through.

Safety: a Content-Security-Policy pinned to the hashes of the inline script
and stylesheet (`default-src 'none'`) blocks every network request, and the
script uses no storage, cookies or navigation, so the page also runs inside an
iframe sandboxed with `allow-scripts` only. Config values reach the page as
JSON data and the DOM as text, never as markup.
