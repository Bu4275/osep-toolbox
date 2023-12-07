using System;
using System.Data.SqlClient;

namespace SQLClient
{
    public class Program
    {
        public static void Main(string[] args)
        {
            String sqlServer = "";
            String database = "";
            if (args.Length == 1)
            {
                sqlServer = args[0];
                String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
                SqlConnection con = new SqlConnection(conString);

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

                String sql = "SELECT SYSTEM_USER;";
                SqlCommand command = new SqlCommand(sql, con);
                SqlDataReader reader = command.ExecuteReader();

                reader.Read();
                Console.WriteLine("Logged in as: " + reader[0]);
                reader.Close();

                con.Close();
            }
            else
            {
                Console.WriteLine("Usage: sql.exe HOSTNAME");
            }

        }
    }
}