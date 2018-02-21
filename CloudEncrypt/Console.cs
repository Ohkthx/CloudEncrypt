using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CloudEncrypt
{
    // Settings that will be store inside 'settings.json' that will be loaded.
    class Settings
    {
        public IList<string> DirectoryRoots { get; set; } = new List<string>();
        public string BackupDirectory { get; set; } = @"C:\Backup\";
        public Tuple<string, string> Hashes { get; set; }
    }

    partial class Program
    {
        private static int m_offset = 0;

        // Verifies the lock file, if it doesn't exist- it creates it.
        private static bool CheckLockFile()
        {
            string lockFile = @"lock.lck";
            Console.WriteLine(" => Checking lock file.");
            if (!File.Exists(lockFile))
            {
                Console.WriteLine($"  => '{lockFile}' does not exist. Creating.");
                if (Actions.CreateLockFile())
                {
                    Console.WriteLine($"  => '{lockFile}' created.\n");
                    return true;
                }
            }
            else
            {
                Console.WriteLine($"  => '{lockFile}' found, decrypting.");
                if (Actions.ReadLockFile())
                {
                    Console.WriteLine($"  => '{lockFile}' successfully decrypted.\n");
                    return true;
                }
            }

            return false;
        }

        #region Miscellaneous
        #endregion

        #region Settings.Json
        // Creates 'settings.json' and assigns it's default values.
        private static bool CreateSettings()
        {
            return SaveSettings(DefaultSettings());
        }

        private static Settings DefaultSettings()
        {
            Settings settings = new Settings();
            settings.DirectoryRoots.Add(Path.GetFullPath(@"C:\Example\Path\1"));
            settings.DirectoryRoots.Add(Path.GetFullPath(@"C:\Example\Path2\"));
            return settings;
        }

        // Save specified settings- could use global...
        private static bool SaveSettings(Settings settings)
        {
            JObject jo = (JObject)JToken.FromObject(settings);
            try
            {
                File.WriteAllText(m_SettingsFile, jo.ToString());
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(" Error occured:\n  {0}", e.Message);
            }

            return false;
        }

        // On startup, CheckSettings() will be called to ensure it exists- if so, it loads it.
        private static bool CheckSettings()
        {
            Console.WriteLine(" => Checking settings file.");
            if (!File.Exists(m_SettingsFile))
            {
                Console.WriteLine($"  => '{m_SettingsFile}' does not exist. Creating.");
                if (CreateSettings())
                {
                    Console.WriteLine($"  => '{m_SettingsFile}' created.\n");
                    return LoadSettings();
                }
                else
                {
                    return false;
                }
            }

            Console.WriteLine($"  => '{m_SettingsFile}' exists. Loading.");
            if (LoadSettings())
                Console.WriteLine($"  => '{m_SettingsFile}' loaded successfully.\n");
            else
                return false;

            return true;
        }

        // Loads the 'settings.json' file and parse.
        private static bool LoadSettings()
        {
            try
            {
                // Load the file and parse it.
                JObject jo = JObject.Parse(File.ReadAllText(m_SettingsFile));
                m_Settings = JsonConvert.DeserializeObject<Settings>(jo.ToString());

                if (string.IsNullOrEmpty(m_Settings.BackupDirectory))
                    throw new BadSettingsException("'settings.json': BackupDirectory not set.");
                else if (!Path.IsPathRooted(m_Settings.BackupDirectory))
                    throw new BadSettingsException("'settings.json': BackupDirectory does not contain a root directory such as 'C:\\'");
                else if (!Actions.IsValidBackup(m_Settings.DirectoryRoots, m_Settings.BackupDirectory))
                    throw new BadSettingsException("'settings.json': BackupDirectoy path not found or is included in a DirectoryRoots path.");
            }
            catch (JsonReaderException jre)
            {
                // TODO: Add option/prompt to recreate default?
                Console.WriteLine("\n [ERR] Unable to load 'settings.json':\n\t{0}", jre.Message);
                return false;
            }
            catch (BadSettingsException bse)
            {
                // TODO: If missing a BackupDirectory -> prompt for a new one? Could be done above.
                Console.WriteLine("\n [ERR] Loading settings:\n\t{0}", bse.Message);
                if ((m_Settings.BackupDirectory = ReplaceDirectory(true, m_Settings.BackupDirectory)) == string.Empty)
                {  // User opt'd to not update. Return a
                    return false;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("\n [ERR] An unknown error ocurred while loading 'settings.json':\n\t{0}", e.Message);
                return false;
            }

            // Check defaults, empty, recursive BackupDirectory and then prompt for change.
            Settings dummy = DefaultSettings();
            if (dummy.BackupDirectory == m_Settings.BackupDirectory || string.IsNullOrEmpty(m_Settings.BackupDirectory)
                || !Actions.IsValidBackup(m_Settings.DirectoryRoots, m_Settings.BackupDirectory))
            {
                if ((m_Settings.BackupDirectory = ReplaceDirectory(true, m_Settings.BackupDirectory)) == string.Empty)
                    return false;
                else
                    // Save the change.
                    SaveSettings(m_Settings);
            }

            // TODO: Continue to check the other defaults DirectoryRoots here.
            // Make comparison and prompt for removal/change.
            foreach (string dummyDir in dummy.DirectoryRoots)
            {
                for (int i = 0; i < m_Settings.DirectoryRoots.Count; i++)
                {
                    string dir = m_Settings.DirectoryRoots[i];
                    if (Actions.OSFileComparison(m_isWindows, dummyDir, dir))
                    {
                        // Prompt for change in the directory that matches the default settings.
                        // If response is empty, do not save a new directory.
                        string newDir = dir;
                        if ((newDir = ReplaceDirectory(false, dir)) != string.Empty)
                            // Replace the directory.
                            m_Settings.DirectoryRoots[i] = Path.GetFullPath(newDir);
                        else
                            // Received 'string.Empty' => remove it from our list.
                            m_Settings.DirectoryRoots.RemoveAt(i);
                    }
                }
            }

            SaveSettings(m_Settings);

            return true;
        }
        #endregion

        #region Directory Actions
        public static bool NewBackupDirectory(ref Settings settings)
        {
            string offsetP = Actions.GetOffset(m_offset);
            while (true)
            {
                string newDir = Actions.AskString("Type or paste a new Backup Destination Directory [default: none]", m_offset);
                if (string.IsNullOrEmpty(newDir))
                {   // No information provide, return/break;
                    Console.WriteLine(offsetP + "[ ! ] Empty directory name, not updateing Backup Destination Directory.");
                    return false;
                }
                else if (!Actions.ValidateDirectory(newDir))
                {   // Not a valid directory provided, try again.
                    Console.WriteLine(offsetP + "[ ! ] Directory is invalid. Either no root directory provided or it doesn't exists.");
                    continue;
                }
                if (Actions.IsValidBackup(m_Settings.DirectoryRoots, newDir))
                {   // Is valid, passes final test. Return success.
                    Console.WriteLine(offsetP + "[ ! ] Backup Destination Directory updated.");
                    settings.BackupDirectory = Path.GetFullPath(newDir);
                    return true;
                }
                else
                {   // Directory check failed, likely part of the directory path of an already archived directory.
                    Console.WriteLine(offsetP+ "[ ! ] Not a valid directory. Likely is included inside of a directory set to be archived.");
                }
            }
        }

        public static string ReplaceDirectory(bool backup, string path)
        {
            if (Actions.AskYesNo($"Do you wish to change ({path})", m_offset))
            {
                string newDir = string.Empty;
                if (backup)
                {
                    do
                    {
                        newDir = Actions.AskString("Type or paste new directory", m_offset);
                    }  while (!Actions.IsValidBackup(m_Settings.DirectoryRoots, newDir));
                }
                else
                {
                    // Prompt to add a directory.
                    AddDirectory(ref m_Settings);
                }
                if (string.IsNullOrEmpty(newDir))
                    return string.Empty;
                else
                    return Path.GetFullPath(newDir);
            }
            return Path.GetFullPath(path);
        }

        public static bool AddDirectory(ref Settings settings)
        {
            string offsetP = Actions.GetOffset(m_offset);
            string newDir = string.Empty;
            do
            {
                newDir = Actions.AskString("Type or paste a new directory [default: none]", m_offset);
                if (string.IsNullOrEmpty(newDir))
                {   // Return early if it is empty (user doesn't want to update/add.)
                    Console.WriteLine(offsetP + "[ ! ] Empty directory name, not adding directory.");
                    return false;
                }
                else if (!Actions.ValidateDirectory(newDir))
                {   // Not a valid directory provided, try again.
                    Console.WriteLine(offsetP + "[ ! ] Directory is invalid. Either no root directory provided or it doesn't exist.");
                    continue;
                }
                else if (Actions.OSFileContains(m_isWindows, newDir, settings.BackupDirectory))
                {   // TODO: Maybe check if BackupDirectory contains newDir AND newDir contains BackupDirectory.
                    Console.WriteLine(offsetP + "[ ! ] You attempted to add a faulty directory. (Directory within the Backup Directory)");
                    continue;
                }
                if (!Actions.hasCollisions(settings.DirectoryRoots, newDir))
                {   // No collisions or overlapping directories- Add, break, return.
                    Console.WriteLine(offsetP + "[ ! ] Directory added.");
                    m_Settings.DirectoryRoots.Add(Path.GetFullPath(newDir));
                    return true;
                }
                else
                {
                    Console.WriteLine(offsetP + "[ ! ] Directory already added.");
                    return true;
                }


            } while (true);
        }

        public static void CreateDirectory(string backup, string pathToCreate)
        {
            try
            {
                string root = Path.GetPathRoot(pathToCreate);
                int index = pathToCreate.IndexOf(root);
                string path = (index < 0) ? pathToCreate : pathToCreate.Remove(index, root.Length);


                // Create Directory here.
                Directory.CreateDirectory(Path.Combine(backup, path));
            }
            catch (ArgumentNullException ane)
            { }
            catch (ArgumentException ae)
            { }
            catch (Exception e)
            { }
        }
        #endregion
    }
}
