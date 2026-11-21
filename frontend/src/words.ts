import { usePreferences } from "./workspace";

export function useWords() {
  const { prefs } = usePreferences();
  return (uk: string, en: string) => prefs.language === "uk" ? uk : en;
}
