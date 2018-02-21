using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CloudEncrypt
{
    public static class Actions
    {
        private static Hash m_eHash;    // Hash for encrypting.
        private static Hash m_dHash;    // Hash for decrypting.
        public static bool m_isWindows;

        #region Miscellaneous
        public static string GetOffset(int offset)
        {
            string os = string.Empty;
            for (int i = 0; i < offset; i++)
                os += ' ';
            return os;
        }

        public static bool OSFileComparison(bool isWindows, string file1, string file2)
        {
            string p1 = Path.GetFullPath(file1);
            string p2 = Path.GetFullPath(file2);

            if (isWindows)
                return p1.ToLower() == p2.ToLower();
            return p1 == p2;
        }

        /// <summary>
        ///     Checks if the path of file1 contains the path of file2.
        /// </summary>
        /// <param name="isWindows">If case-sensitivity matters.</param>
        /// <param name="file1">Potential parent path</param>
        /// <param name="file2">Potential child path</param>
        /// <returns>a bool alerting if it contains a path or not.</returns>
        public static bool OSFileContains(bool isWindows, string file1, string file2)
        {
            string p1 = Path.GetFullPath(file1);
            string p2 = Path.GetFullPath(file2);

            if (isWindows)
                return p1.ToLower().Contains(p2.ToLower());
            return p1.Contains(p2);
        }
        #endregion

        #region User Input
        public static bool AskYesNo(string question)
        { return AskYesNo(question, 0); }

        public static bool AskYesNo(string question, int offset)
        {
            while (true)
            {
                string input = AskString($"{question} [yes/no]", offset);
                string i = input.ToLower();

                if (i == "yes" || i == "y" || i == "ya")
                    return true;
                else if (i == "no" || i == "n" || i == "nop" || i == "nope")
                    return false;
            }
        }

        public static string AskString(string question)
        { return AskString(question, 0); }

        public static string AskString(string question, int offset)
        {
            Console.Write("{0}>> {1}: ", GetOffset(offset), question);
            return Console.ReadLine();
        }

        /// <summary>
        ///     Gets a string that is created based on user input.
        /// </summary>
        /// <returns>User input</returns>
        private static string AskPassword()
        {
            return AskPassword(0);
        }

        private static string AskPassword(int offset)
        {
            // Get our password/hash to store locally.
            Console.Write("{0}>> Password: ", GetOffset(offset));

            StringBuilder input = new StringBuilder();
            while (true)
            {
                // "true" masks input to not display to console.
                ConsoleKeyInfo key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter)
                {   // End the string building if [enter] is detected.
                    Console.WriteLine();
                    break;
                }
                else if (key.Key == ConsoleKey.Backspace)
                {   // Remove the last character from the string if detected backspace.
                    if (input.Length > 0)
                        input.Length--;
                }
                else
                {   // Add our key to the stringbuilder.
                    input.Append(key.KeyChar);
                }
            }

            return input.ToString();
        }
        #endregion

        public static void GetHash(out Hash hash)
        {
            hash = new Hash(AskPassword());
        }

        public static void GetHash(byte[] salt, out Hash hash)
        {
            hash = new Hash(AskPassword(), salt);
        }

        public static void GetHash(byte[] salt, int offset, out Hash hash)
        {
            hash = new Hash(AskPassword(offset), salt);
        }

        #region Lockfile
        public static bool CreateLockFile()
        {
            string lockFile = @"lock";
            byte[] data = { 0x6e, 0x33, 0x79, 0x66, 0x6c };

            try
            {
                using (FileStream fs = File.Create(lockFile))
                        fs.Write(data, 0, data.Length);

                // Encrypt and remove the original lock file.
                EncryptFile(lockFile);
                if (File.Exists(lockFile))
                    File.Delete(lockFile);

                return true;
            }
            catch (UnauthorizedAccessException uae)
            {
                Console.WriteLine("  [ERR] Incorrect permissions in current directory to create lockfile.\n\t{0}", uae.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine("  [ERR] Unable to create lock file.\n\t{0}", e.Message);
            }

            if (File.Exists(lockFile))
                File.Delete(lockFile);
            if (File.Exists(lockFile + ".lck"))
                File.Delete(lockFile + ".lck");

            return false;
        }

        public static bool ReadLockFile()
        {
            string lockFile = @"lock.lck";

            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            AES.Padding = PaddingMode.PKCS7;
            AES.Mode = CipherMode.CBC;

            using (FileStream encryptedFileStream = new FileStream(lockFile, FileMode.Open))
            {
                byte[] salt = new byte[Hash.m_SaltSize];
                encryptedFileStream.Read(salt, 0, Hash.m_SaltSize);

                if (m_dHash == null)
                    GetHash(salt, 2, out m_dHash);

                Rfc2898DeriveBytes key = m_dHash.GetDerivedBytes();
                AES.Key = key.GetBytes(AES.KeySize / 8);
                AES.IV = key.GetBytes(AES.BlockSize / 8);

                // Information from lockFile.
                byte[] data;

                try
                {
                    using (CryptoStream cs = new CryptoStream(encryptedFileStream, AES.CreateDecryptor(), CryptoStreamMode.Read))
                    using (MemoryStream ms = new MemoryStream())
                    {
                        byte[] buffer = new byte[1048576];
                        int read;

                        while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            ms.Write(buffer, 0, read);
                        }
                        data = ms.ToArray();
                    }
                    return true;
                }
                catch (CryptographicException)
                {
                    Console.WriteLine("  [ERR] Bad password provided.");
                    return false;
                }
                catch (Exception e)
                {
                    Console.WriteLine("Unknown issue:\n{0}", e.Message);
                    return false;
                }
            }
        }
        #endregion

        #region Encrypt/Decrypt
        public static void EncryptFile(string ifile)
        {
            if (m_eHash == null)
            {
                GetHash(out m_eHash);
            }

            using (FileStream fsCrypt = new FileStream(ifile + ".lck", FileMode.Create))
            {
                RijndaelManaged AES = new RijndaelManaged();
                AES.KeySize = 256;
                AES.BlockSize = 128;
                AES.Padding = PaddingMode.PKCS7;

                Rfc2898DeriveBytes key = m_eHash.GetDerivedBytes();
                AES.Key = key.GetBytes(AES.KeySize / 8);
                AES.IV = key.GetBytes(AES.BlockSize / 8);

                AES.Mode = CipherMode.CBC;

                fsCrypt.Write(m_eHash.GetSalt(), 0, Hash.m_SaltSize);

                using (CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateEncryptor(), CryptoStreamMode.Write))
                using (FileStream fsIn = new FileStream(ifile, FileMode.Open))
                {
                    byte[] buffer = new byte[1048576];
                    int read;

                    while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                        cs.Write(buffer, 0, read);
                }
            }
        }

        public static bool DecryptFile(string ifile)
        {
            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            AES.Padding = PaddingMode.PKCS7;
            AES.Mode = CipherMode.CBC;

            using (FileStream fsCrypt = new FileStream(ifile, FileMode.Open))
            {
                // Create our buffer for extracting our salt from the file.
                byte[] salt = new byte[Hash.m_SaltSize];
                fsCrypt.Read(salt, 0, Hash.m_SaltSize);

                if (m_dHash == null)
                    GetHash(salt, 2, out m_dHash);

                Rfc2898DeriveBytes key = m_dHash.GetDerivedBytes();
                AES.Key = key.GetBytes(AES.KeySize / 8);
                AES.IV = key.GetBytes(AES.BlockSize / 8);

                try
                {
                    using (CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateDecryptor(), CryptoStreamMode.Read))
                    using (FileStream newFS = new FileStream(ifile + ".decrypted", FileMode.Create))
                    {
                        byte[] buffer = new byte[1048576];
                        int read;

                        while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            newFS.Write(buffer, 0, read);
                        }
                    }

                    return true;
                }
                catch (CryptographicException)
                {
                    Console.WriteLine("  [ERR] Bad password provided.");
                }
                catch (Exception e)
                {
                    Console.WriteLine(" [ERR] Unknown issue:\n\t{0}", e.Message);
                }

                if (File.Exists(ifile + ".decrypted"))
                    File.Delete(ifile + ".decrypted");

                return false;
            }
        }
        #endregion

        #region File Checks
        /// <summary>
        ///     Validates that the rootDirs do not contain the backupDir. This prevents an infinite loop of archiving.
        /// </summary>
        /// <param name="rootDirs">a list of directories that will be backed up.</param>
        /// <param name="backupDir">the destination directory.</param>
        /// <returns>returns true if it is a valid backupDir</returns>
        public static bool IsValidBackup(IList<string> rootDirs, string backupDir)
        {
            if (!ValidateDirectory(backupDir))
                return false;

            // Iterate each directory and compare.
            foreach (string root in rootDirs)
            {   // floor our strings to lower to check if it matches.
                if (m_isWindows)
                {
                    if (root.ToLower().Contains(backupDir.ToLower()))
                        return false;
                }
                else
                {
                    if (root.Contains(backupDir))
                        return false;
                }
            }

            // Return true if the IList is empty or never encountered false statement.
            return true;
        }

        /// <summary>
        ///     Check if there are collisions of repeating paths inside the list. Just a wrapper for IList.Any()
        /// </summary>
        /// <param name="directories">List of directories to iterate.</param>
        /// <param name="pathToCheck">Directory to check if already exists.</param>
        /// <returns>Returns the result whether or not it exists.</returns>
        public static bool hasCollisions(IList<string> directories, string pathToCheck)
        {
            return directories.Any(d => d == pathToCheck);
        }

        /// <summary>
        ///     Checks if the supplied directory (for root directory) is valid. Makes sure there isn't collisions with
        ///     backupDirectory and that it doesn't already exist within the rootDirs list provided.
        /// </summary>
        /// <param name="rootDirs"></param>
        /// <param name="newDirector"></param>
        /// <returns></returns>
        public static bool IsValidDirectoryRoot(IList<string> rootDirs, string backupDirectory, string pathToCheck)
        {   // This will process invalid directories, automatically checking based on the type of OS.
            if (!OSFileComparison(m_isWindows, pathToCheck, backupDirectory))
                return false;
            else if (!ValidateDirectory(pathToCheck))
                return false;

            foreach(string dir in rootDirs)
                if (!OSFileComparison(m_isWindows, dir, pathToCheck))
                    return false;

            return true;
        }

        /// <summary>
        ///     Verifies that the path supplied is a valid directory and exists.
        /// </summary>
        /// <param name="directory">Path to check.</param>
        /// <returns>true if it is valid, false if it is bad.</returns>
        public static bool ValidateDirectory(string directory)
        {   // IF it is a bad directory with no data, just return and say fuck it.
            if (string.IsNullOrEmpty(directory))
                return false;

            try
            {
                FileAttributes attr = File.GetAttributes(directory);

                if ((attr & FileAttributes.Directory) != FileAttributes.Directory)
                    throw new Exception("Supplied path is not a directory.");

                return true;
            }
            catch (FileNotFoundException)
            { Console.WriteLine(" [ERR] '{0}' was not found.", directory); }
            catch (DirectoryNotFoundException)
            { Console.WriteLine(" [ERR] '{0}' was not found.", directory); }
            catch (UnauthorizedAccessException uae)
            { Console.WriteLine(" [ERR] '{0}' is in accessible.\n\t{1}", directory, uae.Message); }
            catch (Exception e)
            { Console.WriteLine(" [ERR] {0}", e.Message); }

            return false;
        }
        #endregion

        /// <summary>
        ///     Takes an incoming path to check and and outgoing path to save/modify.
        /// </summary>
        /// <param name="ipath">input path or file to process.</param>
        /// <param name="opath">output path (destination) for post-modification.</param>
        public static void ProcessPath(string ipath, string opath)
        {
            try
            {
                // Get the attributes of this path.
                FileAttributes attr = File.GetAttributes(ipath);

                // If it is a directory, get files sub-files and process the sub directories.
                if ((attr & FileAttributes.Directory) == FileAttributes.Directory)
                {
                    if (Directory.Exists(opath))
                    {
                        
                    }

                    try
                    {
                        string[] items = Directory.GetFiles(ipath);

                        foreach (string item in items)
                        {
                            Console.WriteLine(" > File: {0}", item);
                            ProcessPath(item, opath);
                        }

                        string[] dirs = Directory.GetDirectories(ipath);
                        foreach(string dir in dirs)
                        {
                            Console.WriteLine(" > Dir:  {0}", dir);
                            ProcessPath(dir, opath);
                        }
                    }
                    catch (Exception e)
                    { Console.WriteLine("Exception caught: \n{0}", e.Message); }
                }
                else 
                {   // It is a Normal file and not a Directory, do some voodoo.
                    try
                    {
                        Console.WriteLine("*DOING VOODOO*");
                    }
                    catch (Exception e)
                    {
                        throw e;
                    }
                }
            }
            catch (DirectoryNotFoundException)
            {
                Console.WriteLine($" [ERR] Directory: {ipath} not found- ignoring.");
            }
            catch (Exception e)
            {
                Console.WriteLine("Something unimaginable happened!\n Message: \n  {0}", e.Message);
            }
        }
    }
}
