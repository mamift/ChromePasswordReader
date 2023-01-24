using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System;

namespace ChromePasswordReader
{
    public static class Utility
    {
        public static void GetLoginData(string userDataDirPath, List<string> loginDataFiles)
        {
            if (Directory.Exists(userDataDirPath)) {
                foreach (string dir in Directory.GetDirectories(userDataDirPath)) {
                    if (dir.Contains("Profile"))
                        loginDataFiles.Add(dir + @"\Login Data");
                }
            }

            try {
                foreach (string loginFile in loginDataFiles.ToArray()) {
                    if (!File.Exists(loginFile)) {
                        Console.WriteLine($"login file: '{loginFile}' doesn't exist!");
                        continue;
                    }

                    using var con = new SQLiteConnection(@"URI=file:" + loginFile);

                    con.Open();
                    SQLiteDataReader rdr = null;

                    try {
                        using var cmd = new SQLiteCommand(con);
                        cmd.CommandText = "SELECT origin_url, action_url, username_value,password_value from logins ;";
                        rdr = cmd.ExecuteReader();
                    }
                    catch (Exception e) {
                        continue;
                    }
                    
                    var loginFileDir = Directory.GetParent(loginFile);
                    var loginFileDirParent = loginFileDir.Parent;

                    byte[] masterKey = GetMasterKey(loginFileDirParent.FullName);
                    var masterKeyStr = Encoding.Default.GetString(masterKey);
                    
                    if (masterKey == null) throw new Exception("No master key!");

                    while (rdr.Read()) {
                        string password;

                        //string encrypted_string = System.Text.Encoding.Unicode.GetString(encrypted_pass);
                        string encrypted_string = rdr.GetString(3);
                        //Console.WriteLine("encrypted_string:" + encrypted_string);

                        var encryptedData = Encoding.Default.GetBytes(encrypted_string);
                        if (encrypted_string.StartsWith("v10") || encrypted_string.StartsWith("v11")) {
                            //Local State file located in the parent folder of profile folder.
                            password = DecryptWithKey(encryptedData, masterKey);
                        } else {
                            var unprotectedData = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.CurrentUser);
                            password = Encoding.UTF8.GetString(unprotectedData);
                        }

                        Console.WriteLine(
                            $@"{rdr.GetString(0),3},{rdr.GetString(1),-8},{rdr.GetString(2),8},{password,16}");
                        //Console.WriteLine("password:" + password);
                    }
                }
            }
            catch (Exception e) {
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
            var localStateText = File.ReadAllText(filePath);
            var pattern =
                new System.Text.RegularExpressions.Regex("\"encrypted_key\":\"(.*?)\"",
                    System.Text.RegularExpressions.RegexOptions.Compiled).Matches(localStateText);

            foreach (System.Text.RegularExpressions.Match prof in pattern) {
                if (prof.Success)
                    masterKey = Convert.FromBase64String((prof.Groups[1].Value)); //Decode base64
            }

            //Trim first 5 bytes. Its signature "DPAPI"
            byte[] temp = new byte[masterKey.Length - 5];
            Array.Copy(masterKey, 5, temp, 0, masterKey.Length - 5);

            try {
                return ProtectedData.Unprotect(temp, null, DataProtectionScope.CurrentUser);
                //return ProtectedData.Unprotect(masterKey, null, DataProtectionScope.CurrentUser);
            }
            catch (Exception ex) {
                Console.WriteLine(ex.ToString());
                return null;
            }
        }

        public static string DecryptWithKey(byte[] encryptedData, byte[] MasterKey)
        {
            byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }; // IV 12 bytes

            //trim first 3 bytes(signature "v10") and take 12 bytes after signature.
            Array.Copy(encryptedData, 3, iv, 0, 12);

            try {
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
                var decrypted = aesDecryptor.Decrypt(MasterKey, iv, null, data, tag);
                var result = Encoding.UTF8.GetString(decrypted);

                return result;
            }
            catch (Exception ex) {
                Console.WriteLine(ex.ToString());
                return null;
            }
        }
    }
}