using System;
using System.IO;
using Microsoft.UI.Xaml;

namespace Wingnal
{
    /// <summary>Small persisted UI preferences (%LOCALAPPDATA%\Wingnal\ui-theme.txt). Best-effort.</summary>
    internal static class UiSettings
    {
        private static string FilePath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Wingnal", "ui-theme.txt");

        public static ElementTheme LoadTheme()
        {
            try
            {
                return File.Exists(FilePath) && Enum.TryParse(File.ReadAllText(FilePath).Trim(), out ElementTheme t)
                    ? t : ElementTheme.Default;
            }
            catch { return ElementTheme.Default; }
        }

        public static void SaveTheme(ElementTheme theme)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
                File.WriteAllText(FilePath, theme.ToString());
            }
            catch { /* best-effort */ }
        }

        // ── one-time UI flags (e.g. teaching tips shown) ──

        private static string FlagPath(string id) => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Wingnal", $"flag-{id}.txt");

        public static bool FlagSet(string id)
        {
            try { return File.Exists(FlagPath(id)); } catch { return false; }
        }

        public static void SetFlag(string id)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(FlagPath(id))!);
                File.WriteAllText(FlagPath(id), "1");
            }
            catch { /* best-effort */ }
        }

        // ── boolean preferences ──

        public static bool LoadBool(string id, bool fallback)
        {
            try { return File.Exists(FlagPath(id)) ? File.ReadAllText(FlagPath(id)).Trim() == "1" : fallback; }
            catch { return fallback; }
        }

        public static void SaveBool(string id, bool value)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(FlagPath(id))!);
                File.WriteAllText(FlagPath(id), value ? "1" : "0");
            }
            catch { /* best-effort */ }
        }
    }
}
