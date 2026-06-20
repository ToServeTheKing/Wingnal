using System;
using System.Runtime.InteropServices;

namespace Wingnal
{
    /// <summary>Enforces a real minimum window size by subclassing the HWND and handling WM_GETMINMAXINFO,
    /// so dragging stops at the floor (rather than snapping back, as an AppWindow.Changed clamp would).</summary>
    internal static class WindowMinSize
    {
        private const int WM_GETMINMAXINFO = 0x0024;

        // Keep the delegate alive for the lifetime of the process so the GC can't collect the thunk.
        private static SUBCLASSPROC? _proc;
        private static int _minWidth, _minHeight;

        public static void Enforce(IntPtr hwnd, int minWidth, int minHeight)
        {
            _minWidth = minWidth;
            _minHeight = minHeight;
            _proc = SubclassProc;
            SetWindowSubclass(hwnd, _proc, 1, IntPtr.Zero);
        }

        private static IntPtr SubclassProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam,
            uint id, IntPtr data)
        {
            if (msg == WM_GETMINMAXINFO)
            {
                double scale = GetDpiForWindow(hWnd) / 96.0;
                var info = Marshal.PtrToStructure<MINMAXINFO>(lParam);
                info.ptMinTrackSize.X = (int)(_minWidth * scale);
                info.ptMinTrackSize.Y = (int)(_minHeight * scale);
                Marshal.StructureToPtr(info, lParam, false);
                return IntPtr.Zero;
            }
            return DefSubclassProc(hWnd, msg, wParam, lParam);
        }

        private delegate IntPtr SUBCLASSPROC(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam,
            uint id, IntPtr data);

        [DllImport("comctl32.dll", SetLastError = true)]
        private static extern bool SetWindowSubclass(IntPtr hWnd, SUBCLASSPROC proc, uint id, IntPtr data);

        [DllImport("comctl32.dll")]
        private static extern IntPtr DefSubclassProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern uint GetDpiForWindow(IntPtr hwnd);

        [StructLayout(LayoutKind.Sequential)]
        private struct POINT { public int X, Y; }

        [StructLayout(LayoutKind.Sequential)]
        private struct MINMAXINFO
        {
            public POINT ptReserved, ptMaxSize, ptMaxPosition, ptMinTrackSize, ptMaxTrackSize;
        }
    }
}
