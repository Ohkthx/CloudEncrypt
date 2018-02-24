using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.Linq;

namespace CloudEncrypt
{
    public class Hash
    {
        public const int m_SaltSize = 16;

        private byte[] m_Salt;
        private byte[] m_Key;
        private byte[] m_Hash;

        private Rfc2898DeriveBytes m_pbkdf2;
        private Rfc2898DeriveBytes m_backup;

        #region Constructors
        public Hash(string input)
        {
            GenerateHash(input);
        }

        public Hash(string input, byte[] salt)
        {
            GenerateHash(input, salt);
        }

        public Hash(string input, int size)
        {
            GenerateHash(input, size);
        }
        #endregion

        /// <summary>
        ///     A .Net Core implementation of creating a hash from a string.
        /// </summary>
        /// <param name="input">String to create hash from.</param>
        /// <returns>A hash of the input provided.</returns>
        private void GenerateHash(string input)
        {
            // Create our salt from the RNGCryptoServiceProvider wrapper.
            byte[] salt;
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt = new byte[m_SaltSize]);
            }
            GenerateHash(input, salt);
        }

        /// <summary>
        ///     A .Net Core implementation of creating a hash from a string.
        /// </summary>
        /// <param name="input">String to create hash from.</param>
        /// <param name="size">Size of the hash to generate.</param>
        /// <returns>A hash of the input provided.</returns>
        private void GenerateHash(string input, int size)
        {
            // Create our salt from the RNGCryptoServiceProvider wrapper.
            byte[] salt;
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt = new byte[m_SaltSize]);
            }
            GenerateHash(input, salt, size);
        }

        /// <summary>
        ///     A .Net Core implementation of creating a hash from a string.
        /// </summary>
        /// <param name="input">String to create hash from.</param>
        /// <param name="salt">Salt to add to the hash.</param>
        /// <returns>A hash of the input provided.</returns>
        private void GenerateHash(string input, byte[] salt)
        {
            this.GenerateHash(input, salt, 20);
        }

        /// <summary>
        ///     A .Net Core implementation of creating a hash from a string.
        /// </summary>
        /// <param name="input">String to create hash from.</param>
        /// <param name="salt">Salt to add to the hash.</param>
        /// <returns>A hash of the input provided.</returns>
        private void GenerateHash(string input, byte[] salt, int size)
        {
            // Create our bash hash in bytes.
            m_pbkdf2 = new Rfc2898DeriveBytes(input, salt, 10000);
            if (m_backup == null)
                m_backup = m_pbkdf2;

            this.m_Salt = salt;
            this.m_Key = this.m_pbkdf2.GetBytes(size);

            // Combine our generated salt and hash.
            byte[] hash = new byte[m_SaltSize + size];
            Array.Copy(salt, 0, hash, 0, m_SaltSize);
            Array.Copy(this.m_Key, 0, hash, m_SaltSize, size);

            // Convert to string and return.
            //var s = Convert.ToBase64String(hash);
            this.m_Hash = hash;
        }

        /// <summary>
        ///     Checks if the password is valid.
        /// </summary>
        public bool IsValid()
        {
            return string.IsNullOrEmpty(this.ToString());
        }

        public byte[] ToBytes()
        {
            return this.m_Hash;
        }

        public byte[] GetKey()
        {
            return this.m_Key;
        }

        public byte[] GetSalt()
        {
            return this.m_Salt;
        }

        public bool KeyReset()
        {
            if (this.m_backup != null)
            {
                this.m_pbkdf2 = this.m_backup;
                return true;
            }
            return false;
        }

        public Rfc2898DeriveBytes GetDerivedBytes()
        {
            return this.m_pbkdf2;
        }

        public bool Check(string input)
        {
            byte[] salt = new byte[m_SaltSize];
            Array.Copy(this.m_Hash, 0, salt, 0, m_SaltSize);

            Hash hash = new Hash(input, salt);

            return this.Equals(hash);
        }

        #region Overrides
        public override bool Equals(object obj)
        {
            if (obj == null || !(obj is Hash))
            {
                return false;
            }

            return ((Hash)obj).ToString() == this.ToString();
        }

        /* Overrides that are unused.
        public static bool operator ==(Hash p1, Hash p2)
        {
            return p1.ToString() == p2.ToString();
        }

        public static bool operator !=(Hash p1, Hash p2)
        {
            return p1.ToString() != p2.ToString();
        }
        */

        public override string ToString()
        {
            return Convert.ToBase64String(this.m_Hash);
        }

        public override int GetHashCode()
        {
            return this.ToString().GetHashCode();
        }
        #endregion
    }
}
