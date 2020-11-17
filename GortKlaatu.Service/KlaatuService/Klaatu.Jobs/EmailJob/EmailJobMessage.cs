// --------------------------------------------------------------------------------------------------------------------
// <copyright file="EmailJobMessage.cs" company="Gort Technology">
//   Copyright ©2020 Gort Technology
// </copyright>
// <summary>
//   Defines the EmailJobMessage type. These are used to serialize an simple email message to a directory on the
//   service machine, that is parsed by the Email Job and loaded into email messages and sent out.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Soap;

namespace Klaatu.Jobs
{

   [Serializable]
   public class EmailJobMessage
   {
      private string _subject;
      private string _body;
      private string _toList;
      private string _ccList;
      private string _bccList;

      /// <summary>
      /// The Logger
      /// </summary>
      private static readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();

      public EmailJobMessage(string subject, string body, string toList, string ccList, string bccList)
      {
         Subject = subject;
         Body = body;
         ToList = toList;
         CcList = ccList;
         BccList = bccList;
      }

      public EmailJobMessage(string fileName)
      {
         // deserialize into a temp object then load values from that one into this one.
         var msg = Deserialize(fileName);
         Subject = msg.Subject;
         Body = msg.Body;
         ToList = msg.ToList;
         CcList = msg.CcList;
         BccList = msg.BccList;
      }

      public string Serialize(string path)
      {
         if (!Directory.Exists(path))
         {
            Logger.Error("Invalid Serialization Path: " + path);
            throw new DirectoryNotFoundException("Invalid Serialization Path: " + path);
         }

         Guid fng = Guid.NewGuid(); // create a guid to use as a filename. Prevents duplicate email files.
         string fileName = Path.Combine(path, fng + ".email");
         SoapFormatter formatter = new SoapFormatter();
         FileStream stream = new FileStream(fileName, FileMode.Create, FileAccess.Write, FileShare.None);
         try
         {
            formatter.Serialize(stream, this);
         }
         catch (Exception ex)
         {
            Logger.Error("Error serializing message with the subject: \"" + Subject + "\"");
            Logger.Error(ex.Message);
            throw;
         }
         finally
         {
            stream.Close();
         }
         return fileName;
      }

      private static EmailJobMessage Deserialize(string filename)
      {
         SoapFormatter formatter = new SoapFormatter();
         FileStream stream = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.Read);
         try
         {
            // Create a temporary message object to deserialize into.
            return (EmailJobMessage)formatter.Deserialize(stream);
         }
         finally
         {
            stream.Close();
         }
      }


      /// <summary>
      /// Email Subject
      /// </summary>
      public string Subject
      {
         get { return _subject; }
         set { _subject = value; }
      }

      /// <summary>
      /// Email Body
      /// </summary>
      public string Body
      {
         get { return _body; }
         set { _body = value; }
      }

      /// <summary>
      /// Email Address List
      /// </summary>
      public string ToList
      {
         get { return _toList; }
         set { _toList = value; }
      }

      /// <summary>
      /// Email Address CC List
      /// </summary>
      public string CcList
      {
         get { return _ccList; }
         set { _ccList = value; }
      }

      /// <summary>
      /// Email Address BCC List
      /// </summary>
      public string BccList
      {
         get { return _bccList; }
         set { _bccList = value; }
      }
   }
}
