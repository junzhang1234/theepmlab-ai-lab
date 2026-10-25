# TheEPMLab AI Lab

Code for the AI Lab series on [TheEPMLab.com](https://theepmlab.com/blog/): AI agents, Claude, and MCP
with Oracle Cloud EPM.

| Folder | Post | What it is |
|--------|------|------------|
| [claude-code-epm-automate](claude-code-epm-automate/) | AI Lab: Let Claude Code Run Your EPM Automate Jobs, Without Handing Over the Keys | A Claude Code setup that runs the EPM Automate runbook: a guard hook that fails closed, permission rules, a sandbox, and a Skill |

Each folder has its own README and offline tests. Run the tests before anything else.

## Before you use any of it

- **Test environments only** until you have reviewed the code and run it against your own setup.
- **Never put a password, token, or key in these files.** Credentials live in your own `.env` or
  encrypted `.epw` file, outside the repository. `.gitignore` excludes both.
- **Everything is synthetic.** Application names, members, rules, and URLs are examples.
- This is independent work. It is not an Oracle or Anthropic product, and neither reviewed it.

## License

MIT. See [LICENSE](LICENSE).
