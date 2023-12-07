using System;
using System.Data;
using System.Data.SqlClient;

namespace SQL
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "";
            String database = "master";

            if (args.Length == 1)
            {
                sqlServer = args[0];
            }
            else
            {
                Console.WriteLine("Usage: mssqlclient.exe <hostname>");
                Environment.Exit(0);
            }
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
            string exec_sql = "";
            Console.Write("SQL> ");
            exec_sql = Console.ReadLine();
            while (exec_sql != "exit")
            {
                command = new SqlCommand(exec_sql, con);
                reader = command.ExecuteReader();

                int count = reader.FieldCount;
                while (reader.Read())
                {
                    for (int i = 0; i < count; i++)
                    {
                        Console.Write(reader.GetName(i) + ": ");
                        Console.WriteLine(reader.GetValue(i));
                    }
                    Console.WriteLine("==============================");
                }
                reader.Close();
                Console.Write("SQL> ");
                exec_sql = Console.ReadLine();
            }
            con.Close();
        }
    }
}