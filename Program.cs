using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Aes_decryptor_challenge
{
    class Program
    {
        static byte[] iv = Convert.FromBase64String("DkBbcmQo1QH+ed1wTyBynA==");
        static byte[] encryptedText = Convert.FromBase64String("yptyoDdVBdQtGhgoePppYHnWyugGmy0j81sf3zBeUXEO/LYRw+2XmVa0/v6YiSy9Kj8gMn/gNu2I7dPmfgSEHPUDJpNpiOWmmW1/jw/Pt29Are5tumWmnfkazcAb23xe7B4ruPZVxUEhfn/IrZPNZdr4cQNrHNgEv2ts8gVFuOBU+p792UPy8/mEIhW5ECppxGIb7Yrpg4w7IYNeFtX5d9W4W1t2e+6PcdcjkBK4a8y1cjEtuQ07RpPChOvLcSzlB/Bg7UKntzorRsn+y/d72qD2QxRzcXgbynCNalF7zaT6pEnwKB4i05fTQw6nB7SU1w2/EvCGlfiyR2Ia08mA0GikqegYA6xG/EAGs3ZJ0aQUGt0YZz0P7uBsQKdmCg7jzzEMHyGZDNGTj0F2dOFHLSOTT2/GGSht8eD/Ae7u/xnJj0bGgAKMtNttGFlNyvKpt2vDDT3Orfk6Jk/rD4CIz6O/Tnt0NkJLucHtIyvBYGtQR4+mhbfUELkczeDSxTXGDLaiU3de6tPaa0/vjzizoUbNFdfkIly/HWINdHoO83E=");
        static byte[] last26 = new byte[26];
        static double maxiterations = Math.Pow(17, 6);

        static void Main()
        {
            var ur = Stopwatch.StartNew();
            try
            {
                using (RijndaelManaged myRijndael = new RijndaelManaged())
                {
                    myRijndael.IV = iv;
                    myRijndael.Padding = PaddingMode.Zeros;
                    int i = 0;

                    writeStatusToConsole(ur, i);
                    foreach (var first6 in getBaseXCombinations(6, 16))
                    {
                        myRijndael.Key = first6.Concat(last26).ToArray();
                        var decodedText = DecryptStringFromBytes(encryptedText, myRijndael);
                        if (decodedText.Contains("pilot"))
                        {
                            Console.WriteLine();
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("Found! key:{0}", string.Join(",", first6));
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine(decodedText);
                            Console.ReadLine();
                            return;
                        }

                        i++;
                        if (i % 20000 == 0)
                        {
                            writeStatusToConsole(ur, i);
                        }
                    }
                    writeStatusToConsole(ur, i);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e.Message);
            }

            Console.WriteLine("Done in {0}", ur.Elapsed);
            Console.ReadLine();
        }

        private static void writeStatusToConsole(Stopwatch ur, int i)
        {
            Console.CursorLeft = 0;
            Console.Write("{0:n0} % færdig. Der er gået {1}", (i / maxiterations) * 100, ur.Elapsed);
        }

        static IEnumerable<IEnumerable<byte>> getBaseXCombinations(int noOfCiphers, int baseX)
        {
            return noOfCiphers == 0 ? new IEnumerable<byte>[] { Enumerable.Empty<byte>() } :
                Enumerable.Range(0, baseX + 1).SelectMany(i => getBaseXCombinations(noOfCiphers - 1, baseX).Select(sub => (new byte[] { (byte)i }).Concat(sub)));
        }

        static string DecryptStringFromBytes(byte[] cipherText, RijndaelManaged myRijndael)
        {
            using (var msDecrypt = new MemoryStream(cipherText))
            using (var csDecrypt = new CryptoStream(msDecrypt, myRijndael.CreateDecryptor(), CryptoStreamMode.Read))
            using (var srDecrypt = new StreamReader(csDecrypt))
            {
                return srDecrypt.ReadToEnd();
            }
        }
    }
}
