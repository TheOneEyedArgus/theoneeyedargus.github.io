# Deploy Instructions

This directory contains the files for `theoneeyedargus.github.io`.

## What goes where

| Local file | Goes to GitHub Pages repo |
|------------|--------------------------|
| `index.md` | `theoneeyedargus.github.io/index.md` — becomes the homepage |
| `resume.md` | `theoneeyedargus.github.io/resume.md` — becomes `theoneeyedargus.github.io/resume` |
| All `projects/*.md` | `theoneeyedargus.github.io/projects/` — each becomes a subpage |
| The existing report | Move to `theoneeyedargus.github.io/boldtealayer/` — keeps it accessible |

## The existing report won't break

Currently `theoneeyedargus.github.io` shows the BoldTealLayer report directly.

After restructuring:
- `theoneeyedargus.github.io` → portfolio index
- `theoneeyedargus.github.io/boldtealayer/` → the report (moved here)
- Any links to `theoneeyedargus.github.io` still resolve to a working page
- The YARA rule reference still works

## Deployment steps

1. Clone `https://github.com/theoneeyedargus/theoneeyedargus.github.io`
2. Move the current report HTML into a `boldtealayer/` subfolder
3. Copy these files into the repo root
4. Push to main
5. GitHub Pages auto-deploys within 1-2 minutes
