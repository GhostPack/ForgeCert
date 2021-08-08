using CommandLine;
using Org.BouncyCastle.Math;

namespace ForgeCert
{
    class CommandLineOptions
    {
        [Option("CaCertPath", Required = true, HelpText = "CA private key as a .pfx or .p12 file")]
        public string CaKeyPath { get; set; }

        [Option("CaCertPassword", Required = false, HelpText = "Password to the CA private key file")]
        public string CaKeyPassword { get; set; }

        [Option("Subject", Required = false, HelpText = "Subject name in the certificate", Default = "CN=User")]
        public string Subject { get; set; }

        [Option("SubjectAltName", Required = true, HelpText = "UPN of the user to authenticate as")]
        public string SubjectAltName { get; set; }

        [Option("NewCertPath", Required = true, HelpText = "Path where to save the new .pfx certificate")]
        public string OutputCertPath { get; set; }

        [Option("NewCertPassword", Required = true, HelpText = "Password to the .pfx file")]
        public string OutputCertPassword { get; set; }

        [Option("CRL", Required = false, HelpText = "ldap path to a CRL for the forged certificate")]
        public string CRLPath { get; set; }

        [Option("Serial", Required = false, HelpText = "serial number for the forged certificate")]
        public BigInteger SerialNumber { get; set; }
    }
}