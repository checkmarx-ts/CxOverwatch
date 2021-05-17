// --------------------------------------------------------------------------------------------------------------------
// <copyright file="QuartzTests.cs" company="Gort Technology">
//   Copyright ©2020 Phillip H. Blanton (https://Gort.co)
// </copyright>
// <summary>
//   Defines the Unit Test types.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

using NUnit.Framework;

namespace Klaatu.Tests
{
	[TestFixture]
	public class KlaatuTests
	{
		[SetUp]
		public void Setup()
		{
		}

		[TearDown]
		public void Teardown()
		{
		}

		[Test]
		public void SomePassingTest()
		{
			Assert.AreEqual(5, 5);
		}

		[Test]
		public void SomeFailingTest()
		{
			Assert.Greater(5, 7);
		}
	}
}
