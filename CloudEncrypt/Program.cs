using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Runtime.InteropServices;

namespace CloudEncrypt
{
    partial class Program
    {
        private const string m_SettingsFile = @"settings.json";
        private static Settings m_Settings;
        private static Hash m_Hash;
        private static bool m_isWindows;


        static void Main(string[] args)
            => Startup();

        private static void Startup()
        {
            // Grab our OS. This is for file comparisons.
            m_isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
            Actions.m_isWindows = m_isWindows;
            m_offset = 2;

            Console.WriteLine("Recursively encrypts directories and files.\n Created by: d0x1p2\n");

            if (CheckLockFile())
            {
                if (CheckSettings())
                    Handler();
                else
                    Console.ReadLine();
            }
            else
                Console.ReadLine();
        }

        static void TEST(bool test)
        {
            if (!test)
                return;

            if (Actions.AskYesNo("Like pie?", 2))
                Console.WriteLine("Likes pie.");

            if (Actions.AskYesNo("like potato?"))
                Console.WriteLine("Likes potato");
        }

        /// <summary>
        /// This will handle the input from the user. 
        /// Options: 
        ///     Use "help" or check "GenerateHelp()" for more information.
        /// </summary>
        static void Handler()
        {
            TEST(false);

            m_offset = 2;

            string input = string.Empty;
            while ((input = Actions.AskString("Select an option [help]", 1)) != "exit")
            {
                switch (input.ToLower())
                {
                    case "":
                        break;
                    case "check":
                        break;
                    case "encrypt":
                        break;
                    case "decrypt":
                        break;
                    case "purge-local":
                        break;
                    case "tree":
                        PrintTree();
                        break;
                    case "ls":
                    case "dirs":
                    case "directories":
                        PrintDirectories();
                        break;
                    case "dir-add":
                    case "directory-add":
                        AddDirectory(ref m_Settings);
                        PrintDirectories();
                        SaveSettings(m_Settings);
                        Console.WriteLine();
                        break;
                    case "dir-dest":
                    case "directory-dest":
                        NewBackupDirectory(ref m_Settings);
                        PrintDirectories();
                        SaveSettings(m_Settings);
                        Console.WriteLine();
                        break;
                    case "exit":
                        return;
                    case "help":
                    default:
                        GenerateHelp();
                        break;
                }

                input = string.Empty;
            }
        }

        #region Console Commands
        private static void GenerateHash()
        {
            string input = string.Empty;
            Console.Write("Type something text to hash, empty input exits.\nInput: ");
            Hash h = new Hash(Console.ReadLine());
            Console.WriteLine("Generated Hash: {0}", h);

            Console.Write("\nRetype Input: ");
            input = Console.ReadLine();

            Console.WriteLine("Checking Hashes... {0}\n", h.Check(input).ToString());
        }

        private static void GenerateHelp()
        {
            Console.WriteLine();
            // h => help
            // information.
            Dictionary<string, string> h = new Dictionary<string, string>();
            h.Add("help", "Displays various command information.");
            h.Add("check", "Checks all selected directories/files and tells you the changes.");
            h.Add("encrypt", "Processes all changed fiiles and directories by encrypting and moving.");
            h.Add("decrypt", "Decrypts all files and moves them to a directory set as a destination.");
            h.Add("purge-local", "Purges and removes all of the unencrypted ORIGINAL files inside their locations.");
            h.Add("directories", "Lists all directories that are currently set to be archived.");
            h.Add("dirs", "See: directories");
            h.Add("ls", "See: directories");
            h.Add("tree", "Lists a directory tree and files that are going to be archived.");
            h.Add("directory-dest", "Directory that processed information should be sent to.");
            h.Add("dir-dest", "See: directory-dest");
            h.Add("directory-add", "Directory to add to be processed when checking and encrypting.");
            h.Add("dir-add", "See: directory-add");
            h.Add("exit", "Exits the application.");

            // Process our help information and properly printing it.
            int maxSize = 0;
            foreach (KeyValuePair<string, string> item in h)
                if (item.Key.Length > maxSize)
                    maxSize = item.Key.Length;

            // Pring out our help in a pretty fashion.
            foreach (KeyValuePair<string, string> item in h)
            {
                string padded = item.Key.PadRight(maxSize);
                Console.WriteLine(" {0} - {1}", padded, item.Value);
            }

            Console.WriteLine();
        }

        private static void PrintDirectories()
        {
            Console.WriteLine("\n{0}Backup Directory: {1}", Actions.GetOffset(m_offset), m_Settings.BackupDirectory);
            if (m_Settings.DirectoryRoots.Count > 0)
            {
                Console.WriteLine("{0}Directories: ", Actions.GetOffset(m_offset));
                foreach (string dir in m_Settings.DirectoryRoots)
                    Console.WriteLine($"{Actions.GetOffset(m_offset + 1)}{dir}");
            } 
            else
            {
                Console.WriteLine("{0}No directories set to be encrypted and archived.", Actions.GetOffset(m_offset+1));
            }

            Console.WriteLine();
        }

        private static void PrintTree()
        {
            Console.WriteLine("\n{0}Tree: ", Actions.GetOffset(m_offset));
            foreach(string dir in m_Settings.DirectoryRoots)
            {
                Console.WriteLine($"{Actions.GetOffset(m_offset +1)}{dir}");
                Actions.ProcessPath(dir, m_Settings.BackupDirectory);
            }
            Console.WriteLine();
        }
        #endregion
    }
}
