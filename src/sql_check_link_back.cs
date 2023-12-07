using System;
using System.Data.SqlClient;


namespace SQL
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "appsrv01.corp1.com";
            String linkServer = "";
            if (args.Length == 2)
            {
                sqlServer = args[0];
                linkServer = args[1];
            }
            else
            {
                Console.WriteLine("Usage: sql.exe sqlServer linkServer");
            }

            String database = "master";

            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);

            // 連上 sqlServer
            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }

            // 先到 linkServer 再回到 sqlServer ，如果是雙向信任就會變成 sa
            String execCmd = "select mylogin from openquery(\"" + linkServer +"\", 'select mylogin from openquery(\"" + sqlServer + "\", ''select SYSTEM_USER as mylogin'')')";
            SqlCommand command = new SqlCommand(execCmd, con);
            SqlDataReader reader = command.ExecuteReader();

            while (reader.Read())
            {
                Console.WriteLine("Executing as login: " + reader[0]);
            }
            reader.Close();

            con.Close();
        }
    }
}