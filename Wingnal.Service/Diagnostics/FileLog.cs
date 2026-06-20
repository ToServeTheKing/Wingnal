namespace Wingnal.Service.Diagnostics;

/// <summary>
/// Dead-simple append-only log to %LOCALAPPDATA%\Wingnal\wingnal.log for diagnosing live behavior
/// (we can't attach a debugger to the deployed app easily). Best-effort; never throws.
/// </summary>
public static class FileLog
{
    private static readonly object Gate = new();
    private static readonly string Path = System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Wingnal", "wingnal.log");

    public static string LogPath => Path;

    /// <summary>Dumps raw bytes next to the log for offline analysis (e.g. an undecryptable envelope).</summary>
    public static void Dump(string fileName, byte[] bytes)
    {
        try
        {
            string dir = System.IO.Path.GetDirectoryName(Path)!;
            Directory.CreateDirectory(dir);
            File.WriteAllBytes(System.IO.Path.Combine(dir, fileName), bytes);
        }
        catch
        {
            // best-effort
        }
    }

    public static void Write(string message)
    {
        try
        {
            string line = $"{DateTime.Now:HH:mm:ss.fff}  {message}{Environment.NewLine}";
            lock (Gate)
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
                File.AppendAllText(Path, line);
            }
        }
        catch
        {
            // Logging must never break the app.
        }
    }
}
