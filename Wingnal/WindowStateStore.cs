using System;
using System.IO;
using System.Text.Json;

namespace Wingnal
{
    /// <summary>Remembered window placement (physical pixels).</summary>
    internal sealed record WindowPlacement(int X, int Y, int Width, int Height);

    /// <summary>Persists the main window's size/position so the app reopens where the user left it
    /// (%LOCALAPPDATA%\Wingnal\window.json). Best-effort: any IO/parse failure just falls back to defaults.</summary>
    internal static class WindowStateStore
    {
        private static string FilePath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Wingnal", "window.json");

        public static WindowPlacement? Load()
        {
            try
            {
                return File.Exists(FilePath)
                    ? JsonSerializer.Deserialize<WindowPlacement>(File.ReadAllText(FilePath))
                    : null;
            }
            catch { return null; }
        }

        public static void Save(WindowPlacement placement)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
                File.WriteAllText(FilePath, JsonSerializer.Serialize(placement));
            }
            catch { /* best-effort */ }
        }
    }
}
