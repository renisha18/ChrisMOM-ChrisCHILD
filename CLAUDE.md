# Chris-Mom & Chris-Child (v2: multi-group)

Stack: server/ = Node + Express JSON API under /api (Postgres pg Pool on Neon, passport-local, bcrypt, express-session + connect-pg-simple, keep encrypt/decrypt helpers). client/ = React + Vite + react-router + framer-motion, plain CSS modules. Vite proxies /api to Express in dev; in production Express serves client/dist. One root package.json with scripts: dev (runs both via concurrently), build, start.

## Data
- users(id, username unique, password_hash, created_at)
- groups(id, name, description, invite_code unique (random 8 chars), admin_id -> users, drawn_at null, created_at)
- group_members(id, group_id, display_name, user_id null -> users, assigned_child encrypted (child's member id) null, revealed_at null)
  unique(group_id, display_name), unique(group_id, user_id)
- groups.dares_enabled boolean default false (migrations/002_dares.sql)
- dares(id, group_id, from_member_id, to_member_id, text varchar(280), created_at, seen_at null, done_at null)

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

Dares (optional, groups.dares_enabled; toggle on /groups/new and admin settings modal):
- POST /api/groups/:id/dares {text}: members only, after draw. Sender = my member row, recipient = my assigned child (server-side only). Trimmed 1-280 chars, max 10 per rolling 24h per sender.
- GET /api/groups/:id/dares: {sent, received}; received never exposes sender; marks received seen. POST /api/dares/:id/done: recipient only.
- GET /api/groups includes new_dares (unseen count) -> Dashboard ticket badge "N new dares".
- Group page: admin gets "Send a dare" card under Invite; members get a "Send dare" pill beside the description note. Compose modal -> confirm modal -> toast. "Dares for you" (From your Chris-Mom + Done) and "Dares you sent" cards. Disabled before draw.

Admin management (Settings modal; all server-side admin-only, ids always re-checked against the group; routes in server/routes/manage.js):
- POST /api/groups/:id/members {name}: add (before draw only). PATCH .../members/:mid {displayName}: rename any time, unique case-insensitive.
- DELETE .../members/:mid: remove (before draw; after draw -> "Reset the draw first"; never yourself).
- POST .../members/:mid/unclaim: set user_id null, keep assignment/revealed_at, so the name can be claimed again via invite with a new account.
- POST /api/groups/:id/reset: one transaction clears assigned_child, revealed_at, drawn_at and deletes the group's dares.
- POST /api/groups/:id/transfer {memberId}: target must be a joined member; old admin becomes a normal member.
- DELETE /api/groups/:id {confirmName}: must equal group name (UI makes admin type it); cascades; client goes to /dashboard.
- Members: POST /api/groups/:id/leave (members panel; before draw only; admin must transfer first; after draw UI says "Ask the admin"). Deletes the member row.
- Each action opens a themed Modal confirm; the settings modal hides while an action modal is open.

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
- Layout: full-width cream background (no gingham) with faint snowflake/star sprinkle. Content container max-width 1200px, centered, 32px padding (16px on mobile). Responsive: desktop uses multi-column grids, mobile (<768px) stacks to one column.max-width 480px, mobile-first, with faint snowflake/star sprinkle.
- Buttons: pill shape. Primary green-dark with cream text; secondary red; outline variant.
- Motifs (CSS/inline SVG only, no copied images): hanging baubles, ticket stubs with notched/zigzag edges, kraft gift tags with twine, paper note with paperclip on red envelope, small bows.
- Green sections use a faint line-pattern of bows.
- Keep all logic unchanged; styling and markup only. Respect prefers-reduced-motion.