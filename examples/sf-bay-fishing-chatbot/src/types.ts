export type FishableStatus = "fishable" | "verify" | "not-fishable";

export type WaterType =
  | "freshwater"
  | "bay"
  | "ocean"
  | "reservoir"
  | "pier"
  | "creek"
  | "warning";

export type FilterTag =
  | "freshwater"
  | "bay-saltwater"
  | "ocean-pier"
  | "reservoir"
  | "family"
  | "shore"
  | "pier"
  | "stocked"
  | "striped-bass"
  | "halibut"
  | "surfperch"
  | "bass"
  | "trout"
  | "no-district-permit"
  | "verify-rules"
  | "warning";

export type Source = {
  label: string;
  url: string;
};

export type FishingSpot = {
  id: string;
  name: string;
  area: string;
  coordinates: { lat: number; lng: number };
  status: FishableStatus;
  waterType: WaterType;
  summary: string;
  expectedSpecies: string[];
  seasonality: string;
  tactics: string[];
  permitNotes: string;
  accessNotes: string;
  amenities: string[];
  cautions: string[];
  sourceNotes: string[];
  sources: Source[];
  tags: FilterTag[];
  baselineScore: number;
};

export type CommunityNote = {
  id: string;
  spotId?: string;
  spotName?: string;
  area?: string;
  date?: string;
  species?: string;
  bait?: string;
  condition?: string;
  note: string;
  sourceLabel: string;
  createdAt: string;
};

export type CatchReport = {
  id: string;
  spotId: string;
  species: string;
  bait: string;
  date: string;
  timeOfDay: string;
  tide: string;
  crowd: "Quiet" | "Moderate" | "Busy" | "Unknown";
  note: string;
  rating: number;
  createdAt: string;
};

export type ChatMessage = {
  id: string;
  role: "user" | "assistant";
  text: string;
  chips: string[];
};
