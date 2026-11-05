import { StrictMode, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { fishingSpots } from "./data/spots";
import type { CatchReport, ChatMessage, CommunityNote, FilterTag, FishingSpot } from "./types";
import "./styles.css";

const storageKeys = {
  reports: "sf-bay-fishing-chatbot:reports",
  notes: "sf-bay-fishing-chatbot:community-notes",
  chat: "sf-bay-fishing-chatbot:chat",
};

const filterOptions: { tag: FilterTag; label: string }[] = [
  { tag: "freshwater", label: "Freshwater" },
  { tag: "bay-saltwater", label: "Bay/salt" },
  { tag: "ocean-pier", label: "Ocean/pier" },
  { tag: "reservoir", label: "Reservoir" },
  { tag: "family", label: "Family" },
  { tag: "shore", label: "Shore" },
  { tag: "pier", label: "Pier" },
  { tag: "stocked", label: "Stocked" },
  { tag: "striped-bass", label: "Striper" },
  { tag: "halibut", label: "Halibut" },
  { tag: "surfperch", label: "Surfperch" },
  { tag: "bass", label: "Bass" },
  { tag: "trout", label: "Trout" },
  { tag: "no-district-permit", label: "State license only" },
  { tag: "verify-rules", label: "Verify rules" },
  { tag: "warning", label: "Warning" },
];

const suggestedPrompts = [
  "Where should I take kids fishing this weekend near Fremont?",
  "Best pier for striped bass without a boat?",
  "Freshwater trout spots within 45 minutes of San Jose?",
  "What should I try at Pacifica Pier?",
  "Compare Quarry Lakes, Lake Chabot, and Del Valle for a beginner.",
  "Use my imported notes and tell me where people seem to be catching halibut.",
];

function readStorage<T>(key: string, fallback: T): T {
  try {
    const raw = window.localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function writeStorage<T>(key: string, value: T) {
  window.localStorage.setItem(key, JSON.stringify(value));
}

function id(prefix: string) {
  if (window.crypto?.randomUUID) {
    return `${prefix}-${window.crypto.randomUUID()}`;
  }
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function normalize(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9\s/-]/g, " ").replace(/\s+/g, " ").trim();
}

function tokens(value: string) {
  return normalize(value)
    .split(" ")
    .filter((token) => token.length > 2);
}

const genericSpotTokens = new Set([
  "area",
  "bay",
  "creek",
  "fishing",
  "lake",
  "marina",
  "park",
  "pier",
  "point",
  "pond",
  "recreation",
  "regional",
  "reservoir",
  "shoreline",
  "the",
]);

function spotMatchScore(text: string, spot: FishingSpot) {
  const textTokens = new Set(tokens(text));
  const nameTokens = tokens(spot.name).filter((token) => !genericSpotTokens.has(token));
  const areaTokens = tokens(spot.area).filter((token) => !genericSpotTokens.has(token));
  let score = 0;
  for (const token of nameTokens) {
    if (textTokens.has(token)) {
      score += 3;
    }
  }
  for (const token of areaTokens) {
    if (textTokens.has(token)) {
      score += 1;
    }
  }
  return score;
}

function findSpotInText(text: string) {
  const [best] = fishingSpots
    .map((spot) => ({ spot, score: spotMatchScore(text, spot) }))
    .filter(({ score }) => score >= 3)
    .sort((a, b) => b.score - a.score);
  return best?.spot;
}

function findSpotByName(name: string | undefined) {
  if (!name) {
    return undefined;
  }
  const normalized = normalize(name);
  return fishingSpots.find((spot) => {
    const spotName = normalize(spot.name);
    return spotName.includes(normalized) || normalized.includes(spotName);
  });
}

function scoreSpot(spot: FishingSpot, query: string, notes: CommunityNote[], reports: CatchReport[]) {
  const queryTokens = tokens(query);
  const haystack = normalize(
    [
      spot.name,
      spot.area,
      spot.waterType,
      spot.summary,
      spot.expectedSpecies.join(" "),
      spot.tactics.join(" "),
      spot.tags.join(" "),
      spot.cautions.join(" "),
    ].join(" "),
  );

  let score = spot.baselineScore / 10;
  for (const token of queryTokens) {
    if (haystack.includes(token)) {
      score += 8;
    }
  }

  const linkedNotes = notes.filter((note) => note.spotId === spot.id || normalize(note.spotName ?? "") === normalize(spot.name));
  const linkedReports = reports.filter((report) => report.spotId === spot.id);
  score += Math.min(linkedNotes.length * 4, 12);
  score += Math.min(linkedReports.length * 3, 9);

  if (spot.status === "not-fishable") {
    score -= 20;
  }
  if (query.includes("kid") && spot.tags.includes("family")) {
    score += 12;
  }
  if (query.includes("beginner") && spot.tags.includes("family")) {
    score += 8;
  }
  if (query.includes("without a boat") && (spot.tags.includes("pier") || spot.tags.includes("shore"))) {
    score += 10;
  }

  return score;
}

function topMatches(query: string, notes: CommunityNote[], reports: CatchReport[]) {
  return fishingSpots
    .map((spot) => ({ spot, score: scoreSpot(spot, query, notes, reports) }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 4);
}

function reportSummary(spot: FishingSpot, reports: CatchReport[]) {
  const linked = reports.filter((report) => report.spotId === spot.id);
  if (!linked.length) {
    return "No local user reports yet.";
  }

  const avg = linked.reduce((sum, report) => sum + report.rating, 0) / linked.length;
  const latest = linked.slice().sort((a, b) => b.date.localeCompare(a.date))[0];
  return `${linked.length} user report${linked.length === 1 ? "" : "s"}, avg ${avg.toFixed(1)}/5. Latest: ${latest.species || "species not set"} on ${latest.date || "undated"} using ${latest.bait || "bait not set"}.`;
}

function noteSummary(spot: FishingSpot, notes: CommunityNote[]) {
  const linked = notes.filter((note) => note.spotId === spot.id || normalize(note.spotName ?? "") === normalize(spot.name));
  if (!linked.length) {
    return "No imported community notes matched to this spot.";
  }
  return linked
    .slice(-2)
    .map((note) => `${note.sourceLabel}: ${note.species ? `${note.species} - ` : ""}${note.note}`)
    .join(" ");
}

function noteSearchText(note: CommunityNote) {
  return [note.spotName, note.area, note.species, note.bait, note.condition, note.note, note.sourceLabel].filter(Boolean).join(" ");
}

function matchingGeneralNotes(query: string, notes: CommunityNote[]) {
  const queryTokens = tokens(query).filter((token) => !["community", "group", "imported", "notes", "private", "people"].includes(token));
  if (!queryTokens.length) {
    return [];
  }
  return notes
    .filter((note) => !note.spotId)
    .map((note) => {
      const haystack = normalize(noteSearchText(note));
      const score = queryTokens.reduce((sum, token) => sum + (haystack.includes(token) ? 1 : 0), 0);
      return { note, score };
    })
    .filter(({ score }) => score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 3)
    .map(({ note }) => note);
}

function buildAnswer(query: string, notes: CommunityNote[], reports: CatchReport[]): ChatMessage {
  const normalized = normalize(query);
  const matches = topMatches(normalized, notes, reports);
  const generalNotes = matchingGeneralNotes(normalized, notes);
  const needsClarifying =
    !/(fresh|salt|bay|ocean|pier|shore|kid|family|trout|bass|halibut|perch|catfish|fremont|san jose|sf|san francisco|boat)/.test(
      normalized,
    );
  const compareMode = normalized.includes("compare");
  const communityMode = normalized.includes("community") || normalized.includes("imported") || normalized.includes("group");

  const lines: string[] = [];
  if (needsClarifying) {
    lines.push(
      "I can narrow this down better if you tell me freshwater vs saltwater, target species, shore/pier access, and how far you want to drive.",
    );
  }

  if (compareMode) {
    lines.push("Short comparison:");
  } else if (communityMode) {
    lines.push("Using public seed data plus your private local imports, the strongest matches are:");
  } else {
    lines.push("Best local matches from the available data:");
  }

  for (const { spot } of matches.slice(0, 3)) {
    const status = spot.status === "not-fishable" ? "not fishable warning" : spot.status === "verify" ? "verify first" : "fishable";
    lines.push(
      `${spot.name} (${spot.area}) - ${status}. Targets: ${spot.expectedSpecies.join(", ")}. ${spot.summary}`,
    );
    lines.push(`Tactics: ${spot.tactics[0]}`);
    lines.push(`Community/user context: ${noteSummary(spot, notes)} ${reportSummary(spot, reports)}`);
  }

  if (generalNotes.length) {
    lines.push("Relevant unmatched private notes:");
    for (const note of generalNotes) {
      lines.push(`${note.sourceLabel}: ${note.species ? `${note.species} - ` : ""}${note.note}`);
    }
  }

  lines.push(
    "Before going, verify current rules, closures, licenses, water quality, fish consumption advisories, tides, and posted signs.",
  );

  const hasPrivateNotes =
    notes.length > 0 && (generalNotes.length > 0 || matches.some(({ spot }) => notes.some((note) => note.spotId === spot.id)));
  const hasReports = reports.length > 0 && matches.some(({ spot }) => reports.some((report) => report.spotId === spot.id));

  return {
    id: id("assistant"),
    role: "assistant",
    text: lines.join("\n\n"),
    chips: [
      "public seed data",
      hasPrivateNotes ? "private community notes" : "no matched community notes",
      hasReports ? "user reports" : "no matched reports",
      "verify current status",
    ],
  };
}

function parseCommunityNotes(input: string): CommunityNote[] {
  const now = new Date().toISOString();
  const trimmed = input.trim();
  if (!trimmed) {
    return [];
  }

  try {
    const parsed = JSON.parse(trimmed) as unknown;
    if (Array.isArray(parsed)) {
      return parsed
        .map((item): CommunityNote | undefined => {
          if (!item || typeof item !== "object") {
            return undefined;
          }
          const source = item as Record<string, unknown>;
          const spotName = typeof source.spotName === "string" ? source.spotName : undefined;
          const spot = findSpotByName(spotName);
          const note = typeof source.note === "string" ? source.note : "";
          if (!note.trim()) {
            return undefined;
          }
          const communityNote: CommunityNote = {
            id: id("note"),
            note,
            sourceLabel: typeof source.sourceLabel === "string" ? source.sourceLabel : "Private community note",
            createdAt: now,
          };
          if (spot?.id) {
            communityNote.spotId = spot.id;
          }
          if (spot?.name ?? spotName) {
            communityNote.spotName = spot?.name ?? spotName;
          }
          if (typeof source.area === "string" || spot?.area) {
            communityNote.area = typeof source.area === "string" ? source.area : spot?.area;
          }
          if (typeof source.date === "string") {
            communityNote.date = source.date;
          }
          if (typeof source.species === "string") {
            communityNote.species = source.species;
          }
          if (typeof source.bait === "string") {
            communityNote.bait = source.bait;
          }
          if (typeof source.condition === "string") {
            communityNote.condition = source.condition;
          }
          return communityNote;
        })
        .filter((note): note is CommunityNote => Boolean(note));
    }
  } catch {
    // Plain text import path below.
  }

  return trimmed
    .split(/\n\s*\n/)
    .map((paragraph) => paragraph.trim())
    .filter(Boolean)
    .map((paragraph) => {
      const spot = findSpotInText(paragraph);
      return {
        id: id("note"),
        spotId: spot?.id,
        spotName: spot?.name,
        area: spot?.area,
        note: paragraph,
        sourceLabel: "Private community note",
        createdAt: now,
      };
    });
}

function useLocalState<T>(key: string, fallback: T) {
  const [value, setValue] = useState<T>(() => readStorage(key, fallback));
  const setStored = (next: T) => {
    setValue(next);
    writeStorage(key, next);
  };
  return [value, setStored] as const;
}

function App() {
  const [query, setQuery] = useState("");
  const [selectedSpotId, setSelectedSpotId] = useState(fishingSpots[1].id);
  const [search, setSearch] = useState("");
  const [filters, setFilters] = useState<FilterTag[]>([]);
  const [importText, setImportText] = useState("");
  const [notes, setNotes] = useLocalState<CommunityNote[]>(storageKeys.notes, []);
  const [reports, setReports] = useLocalState<CatchReport[]>(storageKeys.reports, []);
  const [chat, setChat] = useLocalState<ChatMessage[]>(storageKeys.chat, [
    {
      id: "welcome",
      role: "assistant",
      text:
        "Ask about Bay Area fishing by target species, shore/pier access, family constraints, or a specific spot. I will separate public seed data, your reports, and private imported notes.",
      chips: ["public seed data", "local private notes", "verify current status"],
    },
  ]);
  const [reportForm, setReportForm] = useState({
    species: "",
    bait: "",
    date: new Date().toISOString().slice(0, 10),
    timeOfDay: "",
    tide: "",
    crowd: "Unknown" as CatchReport["crowd"],
    rating: 3,
    note: "",
  });

  const selectedSpot = fishingSpots.find((spot) => spot.id === selectedSpotId) ?? fishingSpots[0];

  const filteredSpots = useMemo(() => {
    const normalizedSearch = normalize(search);
    return fishingSpots
      .filter((spot) => {
        const searchMatch =
          !normalizedSearch ||
          normalize([spot.name, spot.area, spot.summary, spot.expectedSpecies.join(" "), spot.tags.join(" ")].join(" ")).includes(
            normalizedSearch,
          );
        const filterMatch = filters.every((filter) => spot.tags.includes(filter));
        return searchMatch && filterMatch;
      })
      .sort((a, b) => {
        const reportBoost =
          reports.filter((report) => report.spotId === b.id).length - reports.filter((report) => report.spotId === a.id).length;
        return b.baselineScore - a.baselineScore + reportBoost;
      });
  }, [filters, reports, search]);

  const selectedNotes = notes.filter((note) => note.spotId === selectedSpot.id);
  const selectedReports = reports.filter((report) => report.spotId === selectedSpot.id);
  const comparison = filteredSpots.slice(0, 4);

  function toggleFilter(tag: FilterTag) {
    setFilters(filters.includes(tag) ? filters.filter((item) => item !== tag) : [...filters, tag]);
  }

  function ask(nextQuery = query) {
    const trimmed = nextQuery.trim();
    if (!trimmed) {
      return;
    }
    const userMessage: ChatMessage = { id: id("user"), role: "user", text: trimmed, chips: [] };
    const assistantMessage = buildAnswer(trimmed, notes, reports);
    setChat([...chat, userMessage, assistantMessage]);
    setQuery("");
  }

  function importNotes() {
    const parsed = parseCommunityNotes(importText);
    if (!parsed.length) {
      return;
    }
    setNotes([...notes, ...parsed]);
    setImportText("");
  }

  function addReport() {
    if (!reportForm.note.trim() && !reportForm.species.trim()) {
      return;
    }
    const nextReport: CatchReport = {
      id: id("report"),
      spotId: selectedSpot.id,
      species: reportForm.species.trim(),
      bait: reportForm.bait.trim(),
      date: reportForm.date,
      timeOfDay: reportForm.timeOfDay.trim(),
      tide: reportForm.tide.trim(),
      crowd: reportForm.crowd,
      note: reportForm.note.trim(),
      rating: reportForm.rating,
      createdAt: new Date().toISOString(),
    };
    setReports([...reports, nextReport]);
    setReportForm({ ...reportForm, species: "", bait: "", timeOfDay: "", tide: "", note: "" });
  }

  return (
    <main className="app-shell">
      <section className="topbar" aria-label="Application header">
        <div>
          <p className="eyebrow">SF Bay Area</p>
          <h1>Fishing Chat</h1>
        </div>
        <div className="top-stats">
          <span>{fishingSpots.length} spots</span>
          <span>{notes.length} private notes</span>
          <span>{reports.length} reports</span>
        </div>
      </section>

      <section className="workspace">
        <aside className="sidebar" aria-label="Spot directory">
          <div className="panel-header">
            <h2>Spots</h2>
            <span>{filteredSpots.length}</span>
          </div>
          <input
            className="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search species, area, access"
          />
          <div className="filter-grid" aria-label="Filters">
            {filterOptions.map((option) => (
              <button
                className={filters.includes(option.tag) ? "filter active" : "filter"}
                key={option.tag}
                onClick={() => toggleFilter(option.tag)}
                type="button"
              >
                {option.label}
              </button>
            ))}
          </div>
          <div className="spot-list">
            {filteredSpots.map((spot) => (
              <button
                className={spot.id === selectedSpot.id ? "spot-card selected" : "spot-card"}
                key={spot.id}
                onClick={() => setSelectedSpotId(spot.id)}
                type="button"
              >
                <span className={`status ${spot.status}`}>{spot.status}</span>
                <strong>{spot.name}</strong>
                <small>{spot.area}</small>
                <span className="species-line">{spot.expectedSpecies.slice(0, 4).join(", ")}</span>
              </button>
            ))}
          </div>
        </aside>

        <section className="chat-panel" aria-label="Chatbot">
          <div className="panel-header">
            <h2>Chat</h2>
            <button type="button" onClick={() => setChat([])}>
              Clear
            </button>
          </div>
          <div className="suggestions">
            {suggestedPrompts.map((prompt) => (
              <button key={prompt} type="button" onClick={() => ask(prompt)}>
                {prompt}
              </button>
            ))}
          </div>
          <div className="messages">
            {chat.map((message) => (
              <article className={`message ${message.role}`} key={message.id}>
                <p>{message.text}</p>
                {message.chips.length > 0 ? (
                  <div className="chips">
                    {message.chips.map((chip) => (
                      <span key={chip}>{chip}</span>
                    ))}
                  </div>
                ) : null}
              </article>
            ))}
          </div>
          <form
            className="ask-row"
            onSubmit={(event) => {
              event.preventDefault();
              ask();
            }}
          >
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Ask about spots, species, access, tides, or imported notes"
            />
            <button type="submit">Ask</button>
          </form>
        </section>

        <aside className="detail-panel" aria-label="Selected spot details">
          <div className="panel-header">
            <h2>{selectedSpot.name}</h2>
            <span className={`status ${selectedSpot.status}`}>{selectedSpot.status}</span>
          </div>
          <div className="bay-map" aria-label="Schematic Bay Area map">
            {fishingSpots.slice(0, 18).map((spot) => (
              <button
                aria-label={spot.name}
                className={spot.id === selectedSpot.id ? "map-pin active" : "map-pin"}
                key={spot.id}
                onClick={() => setSelectedSpotId(spot.id)}
                style={{
                  left: `${Math.max(8, Math.min(88, (spot.coordinates.lng + 122.55) * 105))}%`,
                  top: `${Math.max(7, Math.min(86, (37.98 - spot.coordinates.lat) * 115))}%`,
                }}
                title={spot.name}
                type="button"
              />
            ))}
          </div>
          <p className="summary">{selectedSpot.summary}</p>
          <div className="detail-grid">
            <div>
              <h3>Targets</h3>
              <p>{selectedSpot.expectedSpecies.join(", ")}</p>
            </div>
            <div>
              <h3>Access</h3>
              <p>{selectedSpot.accessNotes}</p>
            </div>
            <div>
              <h3>Tactics</h3>
              <ul>
                {selectedSpot.tactics.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
            <div>
              <h3>Cautions</h3>
              <ul>
                {selectedSpot.cautions.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
          </div>
          <div className="source-list">
            <h3>Sources</h3>
            {selectedSpot.sources.map((source) => (
              <a href={source.url} key={source.url} rel="noreferrer" target="_blank">
                {source.label}
              </a>
            ))}
          </div>
          <div className="advisory">
            Verify rules, closures, licenses, water quality, fish consumption advisories, tides, and posted signs before leaving.
          </div>
        </aside>
      </section>

      <section className="lower-grid">
        <section className="tool-panel">
          <div className="panel-header">
            <h2>Private Notes</h2>
            <button type="button" onClick={() => setNotes([])}>
              Clear
            </button>
          </div>
          <textarea
            value={importText}
            onChange={(event) => setImportText(event.target.value)}
            placeholder='Paste one note per paragraph, or JSON: [{"spotName":"Pacifica Pier","species":"surfperch","note":"..."}]'
          />
          <div className="button-row">
            <button type="button" onClick={importNotes}>
              Import
            </button>
            <span>{notes.length} notes stored locally</span>
          </div>
          <div className="mini-list">
            {(selectedNotes.length ? selectedNotes : notes.slice(-3)).map((note) => (
              <article key={note.id}>
                <strong>{note.spotName ?? "General Bay Area"}</strong>
                <p>{note.note}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="tool-panel">
          <div className="panel-header">
            <h2>Catch Report</h2>
            <button type="button" onClick={() => setReports([])}>
              Clear all
            </button>
          </div>
          <div className="form-grid">
            <input
              value={reportForm.species}
              onChange={(event) => setReportForm({ ...reportForm, species: event.target.value })}
              placeholder="Species"
            />
            <input
              value={reportForm.bait}
              onChange={(event) => setReportForm({ ...reportForm, bait: event.target.value })}
              placeholder="Bait/lure"
            />
            <input
              type="date"
              value={reportForm.date}
              onChange={(event) => setReportForm({ ...reportForm, date: event.target.value })}
            />
            <input
              value={reportForm.timeOfDay}
              onChange={(event) => setReportForm({ ...reportForm, timeOfDay: event.target.value })}
              placeholder="Rough time"
            />
            <input
              value={reportForm.tide}
              onChange={(event) => setReportForm({ ...reportForm, tide: event.target.value })}
              placeholder="Tide if known"
            />
            <select
              value={reportForm.crowd}
              onChange={(event) => setReportForm({ ...reportForm, crowd: event.target.value as CatchReport["crowd"] })}
            >
              <option>Unknown</option>
              <option>Quiet</option>
              <option>Moderate</option>
              <option>Busy</option>
            </select>
          </div>
          <label className="slider">
            Rating {reportForm.rating}/5
            <input
              max="5"
              min="1"
              type="range"
              value={reportForm.rating}
              onChange={(event) => setReportForm({ ...reportForm, rating: Number(event.target.value) })}
            />
          </label>
          <textarea
            value={reportForm.note}
            onChange={(event) => setReportForm({ ...reportForm, note: event.target.value })}
            placeholder={`Report for ${selectedSpot.name}`}
          />
          <div className="button-row">
            <button type="button" onClick={addReport}>
              Add report
            </button>
            <span>{selectedReports.length} for selected spot</span>
          </div>
        </section>

        <section className="tool-panel comparison-panel">
          <div className="panel-header">
            <h2>Compare</h2>
            <span>Top visible</span>
          </div>
          <div className="compare-table">
            {comparison.map((spot) => (
              <article key={spot.id}>
                <strong>{spot.name}</strong>
                <span>{spot.status}</span>
                <span>{spot.expectedSpecies.slice(0, 3).join(", ")}</span>
                <span>{spot.permitNotes}</span>
              </article>
            ))}
          </div>
        </section>
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
