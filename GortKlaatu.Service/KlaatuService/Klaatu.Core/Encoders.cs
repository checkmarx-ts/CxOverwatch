// --------------------------------------------------------------------------------------------------------------------
// <copyright file="Encoders.cs" company="Gort Security">
//   Copyright 2020 Phillip H. Blanton
// </copyright>
// <summary>
//   Utilities for the Klaatu platform.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

using System;
using System.Text;

namespace Klaatu.Core
{
   public class Encoders
   {
      public static string Base64Encode(string plainText)
      {
         var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
         return Convert.ToBase64String(plainTextBytes);
      }

      public static string Base64Decode(string base64EncodedData)
      {
         var base64EncodedBytes = Convert.FromBase64String(base64EncodedData);
         return Encoding.UTF8.GetString(base64EncodedBytes);
      }

      public static string Rot13(string input)
      {
         StringBuilder output = new StringBuilder();
         char[] array = input.ToCharArray();
         foreach (char letter in array)
         {
            int ln = (int)letter;
            if (letter >= 'a' && letter <= 'z')
            {
               if (letter > 'm') ln -= 13;
               else ln += 13;
            }
            if (letter >= 'A' && letter <= 'Z')
            {
               if (letter > 'M') ln -= 13;
               else ln += 13;
            }
            output.Append((char)ln);
         }
         return output.ToString();
      }
   }
}
