﻿using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.IO;

namespace SitefinityWebApp.AuthProvider
{
    public class AuthPropertiesSerializer
    {
        private const int FormatVersion = 1;

        public byte[] Serialize(AuthenticationProperties model)
        {
            using (var memory = new MemoryStream())
            {
                using (var writer = new BinaryWriter(memory))
                {
                    Write(writer, model);
                    writer.Flush();
                    return memory.ToArray();
                }
            }
        }

        public AuthenticationProperties Deserialize(byte[] data)
        {
            using (var memory = new MemoryStream(data))
            {
                using (var reader = new BinaryReader(memory))
                {
                    return Read(reader);
                }
            }
        }

        public static void Write(BinaryWriter writer, AuthenticationProperties properties)
        {
            if (writer == null)
            {
                throw new ArgumentNullException("writer");
            }
            if (properties == null)
            {
                throw new ArgumentNullException("properties");
            }

            writer.Write(FormatVersion);
            writer.Write(properties.Dictionary.Count);
            foreach (var kv in properties.Dictionary)
            {
                writer.Write(kv.Key);
                writer.Write(kv.Value);
            }
        }

        public static AuthenticationProperties Read(BinaryReader reader)
        {
            if (reader == null)
            {
                throw new ArgumentNullException("reader");
            }

            if (reader.ReadInt32() != FormatVersion)
            {
                return null;
            }
            int count = reader.ReadInt32();
            var extra = new Dictionary<string, string>(count);
            for (int index = 0; index != count; ++index)
            {
                string key = reader.ReadString();
                string value = reader.ReadString();
                extra.Add(key, value);
            }
            return new AuthenticationProperties(extra);
        }
    }
}