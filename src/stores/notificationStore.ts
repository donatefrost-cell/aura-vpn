import { useSyncExternalStore } from 'react';
import type { AppNotification, NotificationCategory } from '../types/vpn';

const STORAGE_KEY = 'aura-notifications-v1';
const MAX_NOTIFICATIONS = 80;

export interface NotificationStoreState {
  items: AppNotification[];
  mutedCategories: Record<NotificationCategory, boolean>;
}

const DEFAULT_MUTED: Record<NotificationCategory, boolean> = {
  connection: false,
  subscription: false,
  update: false,
  import: false,
  duplicate: false,
};

function loadInitial(): NotificationStoreState {
  if (typeof window === 'undefined' || !window.localStorage) {
    return { items: [], mutedCategories: { ...DEFAULT_MUTED } };
  }
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return { items: [], mutedCategories: { ...DEFAULT_MUTED } };
    const parsed = JSON.parse(raw) as Partial<NotificationStoreState>;
    return {
      items: Array.isArray(parsed.items) ? parsed.items.slice(0, MAX_NOTIFICATIONS) : [],
      mutedCategories: { ...DEFAULT_MUTED, ...(parsed.mutedCategories ?? {}) },
    };
  } catch {
    return { items: [], mutedCategories: { ...DEFAULT_MUTED } };
  }
}

class NotificationStore {
  private state: NotificationStoreState = loadInitial();
  private listeners = new Set<() => void>();

  subscribe = (l: () => void) => {
    this.listeners.add(l);
    return () => {
      this.listeners.delete(l);
    };
  };

  getSnapshot = () => this.state;

  private persist(next: NotificationStoreState) {
    this.state = next;
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      } catch {
        // Ignore quota errors
      }
    }
    for (const l of this.listeners) l();
  }

  isMuted(category: NotificationCategory): boolean {
    return Boolean(this.state.mutedCategories[category]);
  }

  push(entry: Omit<AppNotification, 'id' | 'createdAt' | 'read'>): boolean {
    if (this.isMuted(entry.category)) {
      return false;
    }
    const item: AppNotification = {
      ...entry,
      id: `notif-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      createdAt: Date.now(),
      read: false,
    };
    this.persist({
      ...this.state,
      items: [item, ...this.state.items].slice(0, MAX_NOTIFICATIONS),
    });
    return true;
  }

  markRead(id: string) {
    this.persist({
      ...this.state,
      items: this.state.items.map((n) => (n.id === id ? { ...n, read: true } : n)),
    });
  }

  markAllRead() {
    this.persist({
      ...this.state,
      items: this.state.items.map((n) => (n.read ? n : { ...n, read: true })),
    });
  }

  remove(id: string) {
    this.persist({
      ...this.state,
      items: this.state.items.filter((n) => n.id !== id),
    });
  }

  clear() {
    this.persist({
      ...this.state,
      items: [],
    });
  }

  toggleMute(category: NotificationCategory) {
    this.persist({
      ...this.state,
      mutedCategories: {
        ...this.state.mutedCategories,
        [category]: !this.state.mutedCategories[category],
      },
    });
  }
}

export const notificationStore = new NotificationStore();

export function useNotifications(): NotificationStoreState {
  return useSyncExternalStore(
    notificationStore.subscribe,
    notificationStore.getSnapshot,
    notificationStore.getSnapshot,
  );
}
