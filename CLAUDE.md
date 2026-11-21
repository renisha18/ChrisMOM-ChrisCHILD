# Chris-Mom & Chris-Child (v2: multi-group)

Stack: server/ = Node + Express JSON API under /api (Postgres pg Pool on Neon, passport-local, bcrypt, express-session + connect-pg-simple, keep encrypt/decrypt helpers). client/ = React + Vite + react-router + framer-motion, plain CSS modules. Vite proxies /api to Express in dev; in production Express serves client/dist. One root package.json with scripts: dev (runs both via concurrently), build, start.

## Data
- users(id, username unique, password_hash, created_at)
- groups(id, name, description, invite_code unique (random 8 chars), admin_id -> users, drawn_at null, created_at)
- group_members(id, group_id, display_name, user_id null -> users, assigned_child encrypted (child's member id) null, revealed_at null)
  unique(group_id, display_name), unique(group_id, user_id)

## Flow
(Paths below are React routes; each is backed by /api endpoints. Protected pages redirect to /login and return to where the user came from.)
/ landing: app name, Play, How to Play
/how-to-play: rules + about
/login, /register (Play goes here; if logged in, skip to /dashboard)
/dashboard: my groups (created or joined) + Create Group
/groups/new: name, description, "your name in this group", member names (add/remove rows)
/groups/:id: name, description, Members panel (right, toggle, shows joined/not joined), chits (left/middle), "Find your Chris-Child" button disabled until drawn.
  Admin only: invite link + "Share on WhatsApp" (wa.me/?text=), "Send Chris-Child" (needs >=3 members, not yet drawn).
/join/:code: group preview + dropdown of unclaimed names -> login or register -> claim name -> /groups/:id

Draw: shuffle all members, each gets the next (last -> first), save in one transaction, set drawn_at. Members locked after draw.
Reveal: pick any chit -> opens to your assigned name, set revealed_at. If revealed_at set, show the opened chit directly.

## Rules
- Every page except landing has a Back button to its logical parent.
- Only members can view a group; only admin can draw or share.
- All routes: async/await + try/catch, never crash; show friendly error messages.
- Keep replies short.

## Design (Christmas, from Taplink inspo)
- Colors: cream #FBF4E6, paper #F3E7D3, kraft #D9C7A7, red #A3161E, red-dark #7E0F15, green #1E4A2E, green-dark #163824, gold #C9A35B, ink #3A2A1E. Define as CSS variables in index.css.
- Fonts (Google): headings "Cormorant SC" 700 uppercase, red; script accents "Pinyon Script"; body "Montserrat".
- Layout: body = red/white gingham (CSS repeating-linear-gradient); content in a centered cream column max-width 480px, mobile-first, with faint snowflake/star sprinkle.
- Buttons: pill shape. Primary green-dark with cream text; secondary red; outline variant.
- Motifs (CSS/inline SVG only, no copied images): hanging baubles, ticket stubs with notched/zigzag edges, kraft gift tags with twine, paper note with paperclip on red envelope, small bows.
- Green sections use a faint line-pattern of bows.
- Keep all logic unchanged; styling and markup only. Respect prefers-reduced-motion.