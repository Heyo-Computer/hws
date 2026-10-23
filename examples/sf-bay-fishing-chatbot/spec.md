# SF Bay Area Fishing Chatbot

Build a deployable chatbot web app for San Francisco Bay Area fishing advice. The app should extend the Fremont fishing holes idea into a broader Bay Area assistant: users can ask where to go, what to target, what bait/tide/time to consider, what permits or access rules matter, and what cautions to verify before leaving.

Use Vite + React + TypeScript unless the project already has a stronger convention. Keep v1 local-first: seed public data in code and store user catch reports, ratings, and imported community notes in browser `localStorage`. Do not add auth, a database, paid APIs, scraping infrastructure, or a backend service.

The app must be deployable through Heyo/heyvm. `npm start` must serve the production build on `0.0.0.0:3000`.

## Private Community Data Boundary

Primary community context for this example:

- San Francisco Bay Area Fishing Group on Facebook

Treat the Facebook group as a private/community source. A member may manually summarize, paste, or import material they are allowed to use. If group admins approve automated assistance, a separate user-supervised collector such as OpenClaw may help turn visible group content into redacted import notes at a conservative pace. The app may store redacted community notes locally, and may support user-provided photos or source references when the user has permission to use them. Do not publish private member-identifying information. Do not bypass login, permissions, CAPTCHA, rate limits, or platform restrictions. Keep the shipped chatbot app reproducible with local imports; any group collection workflow should be optional and separate from the app runtime.

## Source Data

Seed public-source facts from official and public pages. Do not imply real-time conditions. Label sourced claims as public source notes, and tell users to verify current rules, closures, licenses, water quality, fish consumption advisories, tides, and posted signs before going.

Include public sources such as:

- California Department of Fish and Wildlife fishing regulations and license information: https://wildlife.ca.gov/Fishing
- CDFW Fishing in the City, San Francisco Bay Area: https://wildlife.ca.gov/Fishing-in-the-City/SF
- East Bay Regional Park District fishing: https://www.ebparks.org/recreation/fishing
- EBRPD Angler's Edge fish plants: https://www.ebparks.org/recreation/fishing/anglers-edge-online
- EBRPD water quality alerts: https://www.ebparks.org/natural-resources/water-quality
- Don Edwards San Francisco Bay National Wildlife Refuge fishing: https://www.fws.gov/refuge/don-edwards-san-francisco-bay/visit-us/activities/fishing
- San Francisco Recreation and Parks fishing locations where applicable: https://sfrecpark.org/
- California Office of Environmental Health Hazard Assessment fish advisories: https://oehha.ca.gov/fish
- Tide information should be treated as user-verified unless manually entered or linked from a public source.

## Seed Areas And Spots

Include a starter set covering the Bay Area, with Fremont/East Bay spots from the Fremont example plus a broader regional spread.

Required Fremont/East Bay entries:

- Lake Elizabeth
- Quarry Lakes - Horseshoe Lake
- Quarry Lakes - Rainbow Lake
- Shinn Pond
- Snell Pond at Niles Community Park
- Niles Canyon / Alameda Creek
- Dumbarton Fishing Pier
- Coyote Hills / Alameda Creek channel warning entry, marked as not fishable

Add Bay Area entries such as:

- Pacifica Pier
- Oyster Point Pier / Marina area
- Coyote Point Recreation Area
- Candlestick Point State Recreation Area shoreline
- Berkeley Pier / Berkeley Marina area, with current-access verification warning
- San Pablo Reservoir
- Lafayette Reservoir
- Lake Chabot
- Del Valle Regional Park
- Shadow Cliffs Regional Recreation Area
- Loch Lomond Reservoir
- Marin / North Bay shoreline or pier entries with source-backed access notes

Each spot should include:

- Name, area, coordinates, and fishable/not-fishable status
- Water type: freshwater, bay, ocean, reservoir, pier, creek, warning
- Short local-style summary
- Expected species where sourced
- Seasonality notes when sourced or marked as community/user note
- Bait/lure/tide/time hints when sourced, user-provided, or imported as community notes
- Permit/license notes
- Access notes
- Amenities
- Cautions
- Source URLs
- Tags used by filters
- Baseline score used before user ratings exist

## Chatbot Behavior

The first screen should be the usable chatbot plus a compact spot browser, not a marketing landing page.

The chatbot should:

- Answer from structured seeded data, user reports, and imported community notes.
- Cite the basis for each answer: public source, seeded local note, user report, or community note.
- Prefer precise local advice over generic fishing advice.
- Ask a clarifying question when the user omits key constraints such as freshwater vs saltwater, target species, distance, pier access, family friendliness, or license/permit constraints.
- Refuse to claim real-time bite, closure, stocking, water quality, or legal status unless the data source explicitly supports it.
- Always include a short verification reminder for rules, closures, licenses, water quality, consumption advisories, and posted signs.

Useful prompt examples:

- "Where should I take kids fishing this weekend near Fremont?"
- "Best pier for striped bass without a boat?"
- "Freshwater trout spots within 45 minutes of San Jose?"
- "What should I try at Pacifica Pier?"
- "Compare Quarry Lakes, Lake Chabot, and Del Valle for a beginner."
- "Use my imported notes and tell me where people seem to be catching halibut."

## Core UI

- Chat panel with message history and suggested prompts.
- Spot directory with search and filters.
- Selected spot detail panel with source links and cautions.
- Community notes import panel for pasted text or JSON.
- User catch report form with species, bait/lure, date, rough time, tide if known, crowd level, and note.
- Source/confidence chips on chatbot answers.
- Compact advisory panel.

Filters should include:

- Freshwater
- Bay/saltwater
- Ocean/pier
- Family friendly
- Shore access
- Pier access
- Stocked trout/catfish
- Striped bass / halibut / surfperch / bass / trout targets
- No district permit beyond state license
- Rule verification needed
- Warning/not fishable

## Community Notes Import

Support a paste/import flow for user-provided notes.
For admin-approved group collection, use a separate human-supervised workflow that emits the same redacted import format. Do not embed Facebook login, scraping, or browser automation inside the chatbot app itself.

Accepted v1 formats:

- Plain text notes, one observation per paragraph.
- JSON array with optional fields: `spotName`, `area`, `date`, `species`, `bait`, `condition`, `note`, `sourceLabel`.

The app should parse notes conservatively:

- Match notes to known spots when names are clear.
- Keep unmatched notes in a general Bay Area notes bucket.
- Show imported notes as private local data.
- Allow clearing imported notes.
- Do not upload imported notes anywhere.

## Tasks

- [ ] Scaffold the deployable frontend app
  Create a Vite + React + TypeScript project in this directory. Add `npm run dev`, `npm run build`, `npm run preview`, and `npm start`. `npm start` must run a production preview server on `0.0.0.0:3000` for Heyo.

- [ ] Add seeded Bay Area fishing data
  Put typed seed data in a dedicated module. Include the required Fremont entries and broader Bay Area entries. Every source-backed fact needs a visible source link.

- [ ] Build the chatbot
  Implement a local retrieval-style chatbot that searches seeded spot data, user reports, and imported community notes. It should produce practical answers with source/confidence labels and verification reminders.

- [ ] Build the spot browser
  Add ranked spot cards, search, filters, and detail view. Include a simple built-in location graphic or region grouping without external map APIs.

- [ ] Add reports and community notes
  Store user catch reports and imported community notes in `localStorage`. Let users clear imported notes and reports.

- [ ] Add comparison and advisory panels
  Let users compare selected spots by target species, access, permits, amenities, cautions, and source confidence.

- [ ] Polish responsive app styling
  Make the app compact and scan-friendly on desktop and mobile. Avoid oversized hero sections, marketing copy, decorative gradient blobs, and nested cards.

- [ ] Verify locally
  Run `npm install`, `npm run build`, and `npm start`. Confirm `curl -I http://localhost:3000/` returns `200 OK`. Run `npm audit --audit-level=moderate` and report any remaining issues.

- [ ] Verify Heyo preview run path
  Run inside a preview VM or deploy through Heyo/heyvm. Confirm the public preview URL for port `3000` returns `200 OK`.

## Acceptance Criteria

- The app builds with TypeScript strict mode.
- The UI works without a backend or network-only runtime dependency.
- Chat answers cite whether the answer came from public seeded data, user reports, or imported community notes.
- The app does not scrape Facebook or automate private group access.
- Imported community notes stay in `localStorage`.
- User reports and imported notes persist after page refresh.
- Every seeded fishing spot has visible source links.
- Warning/not-fishable entries are clearly marked.
- The production server works on port `3000`.
- The Heyo preview run path is documented by command output or notes in the final response.
