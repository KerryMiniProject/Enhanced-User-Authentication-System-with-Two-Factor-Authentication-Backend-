﻿using System.Data.SqlClient;


namespace AuthSA.Service.Database
{
    public class Database
    {
        public string ConnectionString = @$"Server=10.112.85.214\SQLEXPRESS, 10433;Database=KE_Mini;User Id=internship;Password=vGDjCJ6UA6kcerkY;Connect Timeout=30;TrustServerCertificate=True;";
        public SqlConnection? Connection;


        public void startConnection()
        {
            Connection = new SqlConnection(ConnectionString);
        }
        public SqlConnection? getConnection()
        {
            return Connection;
        }

        public string getConnectionString()
        {
            return ConnectionString;
        }

        public void closeConnection()
        {
            Connection.Close();
        }

        public void openConnection()
        {
            Connection.Open();
        }


        public void executeQuery(string query)
        {
            SqlCommand getLabelDetails = new SqlCommand(query, Connection);
            getLabelDetails.ExecuteNonQuery();
        }


    }
}
