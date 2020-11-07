using Microsoft.Win32;

namespace FirewallBlocker.Extensions
{
    public static class RegistryKeyExtensions
    {
        public static RegistryKey OpenOrCreateSubKey(this RegistryKey key, string keyName, bool writable = true)
        {
            return key.OpenSubKey(keyName, writable) ?? key.CreateSubKey(keyName, writable);
        }
    }
}
