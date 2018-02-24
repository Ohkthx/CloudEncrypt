using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CloudEncrypt
{
    public enum Action {  None, Encrypt, Decrypt };

    public static class Actions
    {
        private static Hash m_eHash;    // Hash for encrypting.
        private static Hash m_dHash;    // Hash for decrypting.
        private static Rfc2898DeriveBytes key;
        public static bool m_isWindows;
        public static string m_outputDirectory;
        public static int m_offset = 1;

        #region Miscellaneous
        public static void HashReset()
        {
            m_dHash = null;
            m_eHash = null;
        }

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

        #region GetHash
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
        #endregion

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
                EncryptFile(lockFile, Directory.GetCurrentDirectory());
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

            using (FileStream fsCrypt = new FileStream(lockFile, FileMode.Open))
            {
                byte[] salt = new byte[Hash.m_SaltSize];
                fsCrypt.Read(salt, 0, Hash.m_SaltSize);

                if (m_dHash == null)
                    GetHash(salt, 2, out m_dHash);

                Console.WriteLine("\tDEBUG ReadLockFile:\n\t\tObtained Salt: {0}\n\t\tHash: {1}", Encoding.UTF8.GetString(salt), m_dHash.ToString());


                Rfc2898DeriveBytes key = m_dHash.GetDerivedBytes();
                AES.Key = key.GetBytes(AES.KeySize / 8);
                AES.IV = key.GetBytes(AES.BlockSize / 8);

                // Information from lockFile.
                byte[] data;

                try
                {
                    using (CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateDecryptor(), CryptoStreamMode.Read))
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
        /// <summary>
        ///     Encrypts a file and stores it in the opath (destination directory).
        /// </summary>
        /// <param name="ifile">input file that is to be processed.</param>
        /// <param name="opath">output file destination (directory)</param>
        public static void EncryptFile(string ifile, string opath)
        {
            if (m_eHash == null && m_dHash != null)
            {
                Console.WriteLine("\tDEBUG EncryptFile:\n\t\tGetting new eHash w/ dHash salt\n\t\tdHash: {0}\n\t\tSalt: {1}", m_dHash.ToString(), Encoding.UTF8.GetString(m_dHash.GetSalt()));
                //GetHash(m_dHash.GetSalt(), out m_eHash);
                m_eHash = m_dHash;
                Console.WriteLine("\tDEBUG EncryptFile:\n\t\teHash: {0}", m_eHash.ToString());
            }
            else if (m_eHash == null)
            {
                Console.WriteLine("\tDEBUG EncryptFile:\n\t\tGetting new eHash.");
                GetHash(out m_eHash);
                Console.WriteLine("\tDEBUG EncryptFile:\n\t\teHash: {0}\n\t\tSalt: {1}", m_eHash.ToString(), Encoding.UTF8.GetString(m_eHash.GetSalt()));
            }

            string ifileName = Path.GetFileName(ifile);
            string ofullpath = Path.Combine(opath, ifileName + ".lck");

            // Create our directory if it doesn't exist already.
            Program.CreateDirectory(Path.GetDirectoryName(ofullpath));

            using (FileStream fsCrypt = new FileStream(ofullpath, FileMode.Create))
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
                Console.WriteLine("\tDEBUG EncryptFile:\n\t\tSalt: {0}", Encoding.UTF8.GetString(m_eHash.GetSalt()));

                using (CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateEncryptor(), CryptoStreamMode.Write))
                using (FileStream fsIn = new FileStream(ifile, FileMode.Open))
                {
                    byte[] buffer = new byte[1048576];
                    int read;

                    while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                        cs.Write(buffer, 0, read);
                }
            }

            m_eHash.KeyReset();
            m_dHash.KeyReset();
        }

        /// <summary>
        ///     Decrypts a file and saves it to the opath destination.
        /// </summary>
        /// <param name="ifile">file to be decrypted.</param>
        /// <param name="backup">location of encrypted files.</param>
        /// <param name="oroot">targeted root directory to save decrypted file in.</param>
        /// <returns>a bool if it succeeded or not.</returns>
        public static bool DecryptFile(string ifile, string backup, string oroot)
        {
            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            AES.Padding = PaddingMode.PKCS7;
            AES.Mode = CipherMode.CBC;

            using (FileStream fsCrypt = new FileStream(ifile, FileMode.Open))
            {
                byte[] salt = new byte[Hash.m_SaltSize];
                fsCrypt.Read(salt, 0, Hash.m_SaltSize);

                if (m_dHash == null)
                    GetHash(salt, 2, out m_dHash);

                Console.WriteLine("\tDEBUG DecryptFile:\n\t\tSalt Obtained: {0}\n\t\tHash: {1}", Encoding.UTF8.GetString(salt), m_dHash.ToString());


                Rfc2898DeriveBytes key = m_dHash.GetDerivedBytes();
                AES.Key = key.GetBytes(AES.KeySize / 8);
                AES.IV = key.GetBytes(AES.BlockSize / 8);

                string cleanedPath = CleanBackup(ifile, backup);
                string filename = Path.GetFileName(CleanExtension(ifile));
                string subchild = Path.Combine(cleanedPath, filename);
                string outFile = Path.GetFullPath(oroot + subchild);

                // Create our directory for the file if it doesn't exist.
                Program.CreateDirectory(Path.GetFullPath(oroot + cleanedPath));

                try
                {
                    using (CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateDecryptor(), CryptoStreamMode.Read))
                    using (FileStream fs = new FileStream(outFile, FileMode.Create))
                    {
                        byte[] buffer = new byte[1048576];
                        int read;

                        while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            fs.Write(buffer, 0, read);
                        }
                    }

                    m_dHash.KeyReset();
                    return true;
                }
                catch (CryptographicException ce)
                {
                    Console.WriteLine(Error.Print(m_offset, "Potential password issue", ce));
                }
                catch (Exception e)
                {
                    Console.WriteLine(Error.Print(m_offset, "Unknown issue occured", e));
                }

                m_dHash.KeyReset();
                return false;
            }
        }

        private static string CleanBackup(string filename, string backupRoot)
        {
            try
            {
                int index = filename.IndexOf(backupRoot);
                string path = (index < 0) ? filename : filename.Remove(index, backupRoot.Length);
                return Path.GetDirectoryName(path);
            }
            catch (ArgumentException ae)
            {
                Console.WriteLine(Error.Print(m_offset, "Attempted to clean backup", ae));
            }
            return filename;
        }

        private static string CleanExtension(string filename)
        {
            return (Path.GetExtension(filename) == ".lck") ? Path.GetFileNameWithoutExtension(filename) : filename;
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
                string dir = Path.GetFullPath(directory);
                FileAttributes attr = File.GetAttributes(dir);

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
        ///     Processes a root directory and all sub-directories and files.
        /// </summary>
        /// <param name="action">Action: None, Encrypt, or Decrypt.</param>
        /// <param name="backup">backup directory used to either store data or retrieve it.</param>
        /// <param name="ipath">input path or file to process.</param>
        /// <param name="oroot">output's root directory.</param>
        public static void ProcesssRoot(Action action, string backup, string ipath, string oroot)
        {
            try
            {
                // Get the attributes of this path.
                FileAttributes attr = File.GetAttributes(ipath);

                // If it is a directory, get files sub-files and process the sub directories.
                if ((attr & FileAttributes.Directory) == FileAttributes.Directory)
                {
                    try
                    {
                        string[] items = Directory.GetFiles(ipath);

                        foreach (string item in items)
                        {
                            //Console.WriteLine(" > File: {0}", item);
                            ProcesssRoot(action, backup, item, oroot);
                        }

                        string[] dirs = Directory.GetDirectories(ipath);
                        foreach(string dir in dirs)
                        {
                            //Console.WriteLine(" > Dir:  {0}", dir);
                            ProcesssRoot(action, backup, dir, oroot);
                        }
                    }
                    catch (Exception e)
                    { Console.WriteLine("Exception caught: \n{0}", e.Message); }
                }
                else 
                {   // It is a Normal file and not a Directory, do some voodoo.
                    try
                    {
                        if (action == Action.Encrypt)
                        {   // Create the directory and encrypt.
                            string getoutputdir = Program.GetOutputDirectory(oroot, ipath);
                            Actions.EncryptFile(ipath, getoutputdir);
                        }
                        else if (action == Action.Decrypt)
                        {   // Get proper output directory.
                            Actions.DecryptFile(ipath, backup, oroot);
                        }

                    }
                    catch (Exception e)
                    {
                        throw e;
                    }
                }
            }
            catch (DirectoryNotFoundException)
            {
                Console.WriteLine(Error.Print(m_offset, $"Path not found: {ipath}, ignoring."));
            }
            catch (Exception e)
            {
                Console.WriteLine(Error.Print(m_offset, "Something occurred that shouldn't have", e));
            }
        }
    }
}
