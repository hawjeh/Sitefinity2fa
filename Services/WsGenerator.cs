using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace SitefinityWebApp.Services
{
    public static class WsGenerator
    {
        public static string GeneratePassword(string secret, long iterationNumber, int digits = 6)
        {
            byte[] counter = BitConverter.GetBytes(iterationNumber);

            if (BitConverter.IsLittleEndian)
                Array.Reverse(counter);

            byte[] key = Encoding.ASCII.GetBytes(secret);

            HMACSHA1 hmac = new HMACSHA1(key, true);

            byte[] hash = hmac.ComputeHash(counter);

            int offset = hash[hash.Length - 1] & 0xf;

            // Convert the 4 bytes into an integer, ignoring the sign.
            int binary =
                ((hash[offset] & 0x7f) << 24)
                | (hash[offset + 1] << 16)
                | (hash[offset + 2] << 8)
                | (hash[offset + 3]);

            // Limit the number of digits
            int password = binary % (int)Math.Pow(10, digits);

            // Pad to required digits
            return password.ToString(new string('0', digits));
        }

        public static readonly DateTime UNIX_EPOCH = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        private static readonly Dictionary<string, DateTime> _cache;

        static WsGenerator()
        {
            _cache = new Dictionary<string, DateTime>();
        }

        public static string GetPassword(string secret)
        {
            return GetPassword(secret, GetCurrentCounter());
        }

        private static string GetPassword(string secret, long counter, int digits = 6)
        {
            return GeneratePassword(secret, counter, digits);
        }

        private static long GetCurrentCounter()
        {
            return GetCurrentCounter(DateTime.UtcNow, UNIX_EPOCH, 30);
        }

        private static long GetCurrentCounter(DateTime now, DateTime epoch, int timeStep)
        {
            return (long)(now - epoch).TotalSeconds / timeStep;
        }

        private static void CleanCache()
        {
            List<string> keysToRemove = new List<string>(_cache.Count);

            foreach (KeyValuePair<string, DateTime> pair in _cache)
            {
                if ((DateTime.Now - pair.Value).TotalMinutes > 2)
                {
                    keysToRemove.Add(pair.Key);
                }
            }

            foreach (string key in keysToRemove)
            {
                _cache.Remove(key);
            }
        }

        public static bool IsValid(string secret, string password, int checkAdjacentIntervals = 1)
        {
            CleanCache();

            string cache_key = string.Format("{0}_{1}", secret, password);

            if (_cache.ContainsKey(cache_key))
            {
                throw new Exception("You cannot use the same secret/iterationNumber combination more than once.");
            }

            _cache.Add(cache_key, DateTime.Now);

            if (password == GetPassword(secret))
                return true;

            for (int i = 1; i <= checkAdjacentIntervals; i++)
            {
                if (password == GetPassword(secret, GetCurrentCounter() + i))
                    return true;

                if (password == GetPassword(secret, GetCurrentCounter() - i))
                    return true;
            }

            return false;
        }
    }
}