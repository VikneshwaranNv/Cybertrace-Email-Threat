/// <reference types="vite/client" />
import { createClient, SupabaseClient } from '@supabase/supabase-js';

const supabaseUrl =
  (typeof import.meta !== 'undefined' && import.meta.env?.VITE_SUPABASE_URL) ||
  'https://ljkvjqciygxpctoynkvl.supabase.co';
const supabaseAnonKey =
  (typeof import.meta !== 'undefined' && import.meta.env?.VITE_SUPABASE_ANON_KEY) ||
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imxqa3ZqcWNpeWd4cGN0b3lua3ZsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTE3MTU5NzUsImV4cCI6MjEwNzI5MTk3NX0.u6k0muNgvtqBDz9BPRqK9JiSQnBZhp0DAy7lTIcu_yM';

export const isSupabaseConfigured = Boolean(
  supabaseUrl &&
  supabaseAnonKey &&
  supabaseUrl.startsWith('https://') &&
  supabaseAnonKey.length > 20
);

export const supabase: SupabaseClient | null = isSupabaseConfigured
  ? createClient(supabaseUrl, supabaseAnonKey, {
      auth: {
        persistSession: true,
        autoRefreshToken: true,
        detectSessionInUrl: true,
      },
    })
  : null;

