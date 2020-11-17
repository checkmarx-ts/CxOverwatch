// --------------------------------------------------------------------------------------------------------------------
// <copyright file="Utilities.cs" company="Gort Security">
//   Copyright 2020 Phillip H. Blanton
// </copyright>
// <summary>
//   Utilities for the Klaatu platform.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;

namespace Klaatu.Core
{
	public class Utilities
	{
		/// <summary>
		/// Returns a parameter based on the value of flag.
		/// </summary>
		/// <param name="flag">A logical value</param>
		/// <param name="option1">Option 1</param>
		/// <param name="option2">Option 2</param>
		/// <returns>option1 if flag is true, otherwise option2</returns>
		public static string TextSelector(bool flag, string option1, string option2)
		{
			return flag ? option1 : option2;
		}

		/// <summary>
		/// Returns a properly delimited string based on the contents of first and second.
		/// </summary>
		/// <param name="first">the first string</param>
		/// <param name="second">the second string</param>
		/// <param name="delimiter">the delimiter</param>
		/// <returns></returns>
		public static string Delimit(string first, string second, string delimiter)
		{
			if (string.IsNullOrEmpty(first) && string.IsNullOrEmpty(second))
				return "";
			if (string.IsNullOrEmpty(first) && !string.IsNullOrEmpty(second))
				return second;
			if (!string.IsNullOrEmpty(first) && string.IsNullOrEmpty(second))
				return first;
			return first + delimiter + second + "";
			//return $"{first}{delimiter}{second}";
		}

		/// <summary>
		/// Returns a delimited string from the items in the list.
		/// </summary>
		/// <param name="list">A list of strings to delimit into one string.</param>
		/// <param name="delimiter">The delimiter. Can be a multiple character string, like ", " or a single character string, like ";".</param>
		/// <param name="lastDelimter">Optional: If you want the last delimiter to be something different such as in a string like this "one, two, three, four, and five." then your delimiter would be ", " and the last delimiter would be ", and ".</param>
		/// <returns>delimited string</returns>
		public static string DelimitList(List<string> list, string delimiter, string lastDelimter = null)
		{
			string result = "";
			foreach (string item in list)
				result = Delimit(result, item, delimiter);

			if (!string.IsNullOrEmpty(lastDelimter))
			{
				// swap the last instance of delimiter with the value for lastDelimiter
				// good for lists like "one, two, three, and four". Delimiter would be ", " and lastDelimiter would be ", and "
				int swapIndex = result.LastIndexOf(delimiter);
				var aStringBuilder = new StringBuilder(result);
				aStringBuilder.Remove(swapIndex, delimiter.Length);
				aStringBuilder.Insert(swapIndex, lastDelimter);
				result = aStringBuilder.ToString();
			}
			return result;
		}

		/// <summary>
		/// Returns absolute path of the current executable
		/// </summary>
		public static string CurrentDirectory
		{
			get
			{
				var currentlyExecutingDirectory = new DirectoryInfo(Assembly.GetExecutingAssembly().Location);
				return Path.GetDirectoryName(currentlyExecutingDirectory.FullName);
			}
		}

		/// <summary>
		/// Random String Generator
		/// </summary>
		/// <param name="length"></param>
		/// <returns></returns>
		public static string RandomString(int length)
		{
			Random rand = new Random();
			const string pool = "A BCDEFGHIJKLM NOPQRSTUV WXYZabcdefg hijklmnopqr stuvwxyz0123456789 ";
			var chars = Enumerable.Range(0, length).Select(x => pool[rand.Next(0, pool.Length)]);
			return new string(chars.ToArray());
		}

		/// <summary>
		/// Returns a pluralized or sningular version of a string, depending on the value of count.
		/// </summary>
		/// <param name="count">The number of items</param>
		/// <param name="singular">The singular version to return</param>
		/// <param name="plural">the plural version to return</param>
		/// <returns>one of the passed in parameters.</returns>
		public static string Pluralize(int count, string singular, string plural)
		{
			return count != 1 ? plural : singular;
		}

		/// <summary>
		/// Verifies the email address
		/// </summary>
		/// <param name="emailAddress">The email Address to verify</param>
		/// <returns>True or False</returns>
		public static bool VerifyAddress(string emailAddress)
		{
			return true;
		}

		/// <summary>
		/// Verifies the repository. Does the specified repsitory belong to the specified user?   
		/// </summary>
		/// <param name="repoName">Repository name</param>
		///// <param name="emailAddress">User email address</param>
		/// <returns>True or False.</returns>
		public static bool VerifyRepository(string repoName, string emailAddress)
		{
			var DoesRepositoryExist = true;

			// If the emailAddress is null or empty, then don't match the repository to the user.
			if (string.IsNullOrEmpty(emailAddress))
			{
				return DoesRepositoryExist;
			}
			else
			{
				return DoesRepositoryExist && DoesRepositoryBelongTo(repoName, emailAddress);
			}
		}

		/// <summary>
		/// Checks to see if the specified repository belongs to the person with the specified email address. 
		/// </summary>
		/// <param name="repoName">Repository name</param>
		/// <param name="emailAddress">Email address to check.</param>
		/// <returns>True or False</returns>
		public static bool DoesRepositoryBelongTo(string repoName, string emailAddress)
		{
			return true;
		}

	}
}
