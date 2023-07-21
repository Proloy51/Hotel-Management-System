using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;

namespace HotelManagementProject
{
    public class clsUtility
    {
        string EncryptionKey = "Secret Key";
        public SqlConnection Con()
        {
            var configuration = new ConfigurationBuilder().AddJsonFile($"appsettings.json");

            var config = configuration.Build();
            var con = new SqlConnection(config.GetConnectionString("Local"));
            //var con = new SqlConnection("Persist Security Info=False;User ID=sa;password=123123;Initial Catalog=AGLdb;Data Source=localhost;Connection Timeout=10000;");
            //var connection = new MySqlConnection("Server=localhost;Database=db;Uid=sa;Pwd=123123;AllowUserVariables=true; ");
            return con;
        }
        public string DecryptPassword(string pass)
        {
            string decryptedPassword = "";
            try
            {
                byte[] cipherBytes = Convert.FromBase64String(pass);
                using (Aes encryptor = Aes.Create())
                {
                    Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                    encryptor.Key = pdb.GetBytes(32);
                    encryptor.IV = pdb.GetBytes(16);
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(cipherBytes, 0, cipherBytes.Length);
                            cs.Close();
                        }
                        decryptedPassword = Encoding.Unicode.GetString(ms.ToArray());
                    }
                }
            }
            catch (Exception ex)
            {

            }
            return decryptedPassword;
        }
        public string EncryptPassword(string password)
        {
            string encryptedPassword;

            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        byte[] plainTextBytes = Encoding.Unicode.GetBytes(password);
                        cs.Write(plainTextBytes, 0, plainTextBytes.Length);
                        cs.FlushFinalBlock();
                    }

                    byte[] encryptedBytes = ms.ToArray();
                    encryptedPassword = Convert.ToBase64String(encryptedBytes);
                }
            }

            return encryptedPassword;
        }
    }
}
