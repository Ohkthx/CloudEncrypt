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
}
