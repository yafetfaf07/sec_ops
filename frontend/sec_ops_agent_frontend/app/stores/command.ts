import { create } from "zustand";
import type { NLQueryResult } from "~/lib/types";

export interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  text: string;
  result?: NLQueryResult;
  created_at: number;
}

interface CommandState {
  messages: ChatMessage[];
  pending: boolean;
  addMessage: (m: ChatMessage) => void;
  setPending: (p: boolean) => void;
  clear: () => void;
}

export const useCommandStore = create<CommandState>((set) => ({
  messages: [],
  pending: false,
  addMessage: (m) => set((s) => ({ messages: [...s.messages, m] })),
  setPending: (p) => set({ pending: p }),
  clear: () => set({ messages: [], pending: false }),
}));
