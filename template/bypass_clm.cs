using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;


public class HelloWorld
{
	public static void Main(string[] args)
	{
		Runspace rs = RunspaceFactory.CreateRunspace();
		rs.Open();
		PowerShell ps = PowerShell.Create();
		ps.Runspace = rs;
		String cmd = "";
		// Example: cmd += "$ExecutionContext.SessionState.LanguageMode | Out-File -FilePath LanguageMode.txt";
		cmd += "{{code}}";
		ps.AddScript(cmd);
		ps.Invoke();
		rs.Close();
	} 
}
