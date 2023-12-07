using System;
using System.Data.SqlClient;

namespace SQLCMD
{
    public class Program
    {
        public static void Main(string[] args)
        {
            String sqlServer = "";
            String database = "";
            string exec_sql = "";
            if (args.Length == 2)
            {
                sqlServer = args[0];
                exec_sql = args[1];
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

                command = new SqlCommand(exec_sql, con);
                reader = command.ExecuteReader();

                int count = reader.FieldCount;
                while (reader.Read())
                {
                    for (int i = 0; i < count; i++)
                    {
                        Console.WriteLine(reader.GetValue(i));
                    }
                }
                reader.Close();
                con.Close();
            }
            else
            {
                Console.WriteLine("Usage: mssqlcmd.exe HOSTNAME QUERY");

            }
        }
    }
}