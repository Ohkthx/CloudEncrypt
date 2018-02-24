using System;
using System.Collections.Generic;
using System.Text;

namespace CloudEncrypt
{
    class BadSettingsException : Exception
    {
        public BadSettingsException() { }
        public BadSettingsException(string message) : base(message) { }
        public BadSettingsException(string message, Exception inner) : base(message, inner) { }
    }

    class Error
    {
        public static string Print(int offset, string text)
        { return Print(offset, text, null); }

        public static string Print(int offset, string text, Exception e) 
        {
            string message = string.Empty;
            if (e != null)
                message = string.Format("\n{0}{1}", Actions.GetOffset(offset + 1), e.Message);
            return string.Format("{0}[ERR] {1}{2}", Actions.GetOffset(offset), text, message);
        }
    }
}
