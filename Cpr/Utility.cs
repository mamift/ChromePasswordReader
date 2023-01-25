using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System;
using Cpr.Extensions;

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

            string tempCopyOfLoginFile = null;
            try {
                foreach (string loginFile in loginDataFiles.ToArray()) {
                    if (!File.Exists(loginFile)) {
                        Console.WriteLine($"login file: '{loginFile}' doesn't exist!");
                        continue;
                    }

                    tempCopyOfLoginFile = Path.GetTempFileName();
                    File.Copy(loginFile, tempCopyOfLoginFile, true);

                    using var con = new SQLiteConnection(@"URI=file:" + tempCopyOfLoginFile);

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
                    var masterKeyStr = Convert.ToBase64String(masterKey);
                    var mkeyUtf8 = Encoding.UTF8.GetString(masterKey);

                    if (masterKey == null) throw new Exception("No master key!");

                    while (rdr.Read()) {
                        string password;

                        //string encryptedString = System.Text.Encoding.Unicode.GetString(encrypted_pass);
                        string encryptedString = rdr.GetString(3);
                        //Console.WriteLine("encrypted_string:" + encrypted_string);

                        var encryptedData = Encoding.Default.GetBytes(encryptedString);
                        if (encryptedString.StartsWith("v10") || encryptedString.StartsWith("v11")) {
                            //Local State file located in the parent folder of profile folder.
                            //password = DecryptWithKey(encryptedData, masterKey);
                            password = DecryptWithKey2(encryptedData, masterKey);
                            //password = CryptoExtensions.SvcDecryptWithMasterKey(encryptedData, masterKey);
                            //var p2 = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.CurrentUser);
                            //password = Encoding.Default.GetString(p2);
                        }
                        else {
                            var unprotectedData =
                                ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.CurrentUser);
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
            finally {
                if (tempCopyOfLoginFile != null && File.Exists(tempCopyOfLoginFile)) {
                    File.Delete(tempCopyOfLoginFile);
                }
            }
        }

        public static string? GetMasterKeyString(string localStateFolder)
        {
            //Key saved in Local State file
            string filePath = localStateFolder + @"\Local State";

            if (File.Exists(filePath) == false) return null;

            //Get key with regex.
            var localStateText = File.ReadAllText(filePath);
            var pattern =
                new System.Text.RegularExpressions.Regex("\"encrypted_key\":\"(.*?)\"",
                    System.Text.RegularExpressions.RegexOptions.Compiled).Matches(localStateText);

            foreach (System.Text.RegularExpressions.Match prof in pattern) {
                if (prof.Success) {
                    var keyValue = prof.Groups[1].Value;
                    if (!string.IsNullOrWhiteSpace(keyValue)) {
                        return keyValue;
                    }
                }
            }

            return null;
        }

        public static byte[] GetMasterKey(string localStateFolder)
        {
            byte[] masterKey;

            var masterKeyString = GetMasterKeyString(localStateFolder);
            masterKey = Convert.FromBase64String(masterKeyString); //Decode base64

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

        public static string DecryptWithKey2(byte[] encryptedData, byte[] masterKey)
        {
            var aesDecryption = new System.Security.Cryptography.AesGcm(masterKey);
            const int ivLength = 12;
            // IV 12 bytes
            byte[] iv = new byte[ivLength]; 

            //trim first 3 bytes(signature "v10") and take 12 bytes after signature.
            var sourceIndex = 3;
            Array.Copy(encryptedData, sourceIndex, iv, 0, ivLength);

            try {
                //encryptedData without IV
                int encryptedDataStartIndex = sourceIndex + ivLength;
                var encryptedDataLength = encryptedData.Length - encryptedDataStartIndex;
                byte[] payload = new byte[encryptedDataLength];
                Array.Copy(encryptedData, encryptedDataStartIndex, payload, 0, encryptedDataLength);

                const int authTagLength = 16;
                byte[] tag = new byte[authTagLength]; //AuthTag
                var dataLength = payload.Length - authTagLength;
                byte[] data = new byte[dataLength]; //Encrypted Data

                //Last 16 bytes for tag
                Array.Copy(payload, dataLength, tag, 0, authTagLength);

                //encrypted password
                Array.Copy(payload, 0, data, 0, payload.Length - tag.Length);
                Console.WriteLine("tag:" + System.Text.Encoding.Default.GetString(tag));
                
                byte[] decrypted = new byte[payload.Length];
                aesDecryption.Decrypt(nonce: iv, ciphertext: payload, tag: tag, plaintext: decrypted, associatedData: null);
                var result = Encoding.UTF8.GetString(decrypted);

                return result;
            }
            catch (Exception ex) {
                Console.WriteLine(ex.ToString());
                return null;
            }
        }

        public static string DecryptWithKey(byte[] encryptedData, byte[] masterKey)
        {
            byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }; // IV 12 bytes

            //trim first 3 bytes(signature "v10") and take 12 bytes after signature.
            const int ivLength = 12;
            Array.Copy(encryptedData, 3, iv, 0, ivLength);

            try {
                //encryptedData without IV
                const int dataBufferLength = 15;
                byte[] dataBufferWithoutIv = new byte[encryptedData.Length - dataBufferLength];
                Array.Copy(encryptedData, dataBufferLength, dataBufferWithoutIv, 0, encryptedData.Length - dataBufferLength);

                const int authTagLength = 16;
                byte[] tag = new byte[authTagLength]; //AuthTag
                byte[] data = new byte[dataBufferWithoutIv.Length - tag.Length]; //Encrypted Data

                //Last 16 bytes for tag
                Array.Copy(dataBufferWithoutIv, dataBufferWithoutIv.Length - authTagLength, tag, 0, authTagLength);

                //encrypted password
                Array.Copy(dataBufferWithoutIv, 0, data, 0, dataBufferWithoutIv.Length - tag.Length);
                //Console.WriteLine("tag:" + System.Text.Encoding.Default.GetString(tag));

                AesGcm aesDecryption = new AesGcm();
                var decrypted = aesDecryption.Decrypt(key: masterKey, iv: iv, aad: null, cipherText: data, authTag: tag);
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