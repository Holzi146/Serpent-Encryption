using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Threading;

namespace Serpent
{
    public partial class MainWindow : Window
    {
        Thread t_key_length;
        CSerpent serpent;

        public MainWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded_1(object sender, RoutedEventArgs e)
        {
            /* Thread for the real-time keysize */
            t_key_length = new Thread(KeyLength);
            t_key_length.IsBackground = true;
            t_key_length.Start();
        }

        /* ------------ STARTING ENCRYPTION ------------ */

        private void btn_encrypt_Click(object sender, RoutedEventArgs e)
        {
            /* checking for the keysize */
            if ((tbx_key.Text.Length * 4 != 128) && (tbx_key.Text.Length * 4 != 192) && (tbx_key.Text.Length * 4 != 256))
            {
                MessageBox.Show("Wrong keysize!");
                return;
            }

            serpent = new CSerpent();
            tbx_cipher.Text = "";
            /* adding a 0, if the string is not dividable by 32 */
            string plain = tbx_plain.Text.Length % 32 == 0 ? tbx_plain.Text : tbx_plain.Text.PadRight((tbx_plain.Text.Length / 32 + 1) * 32, '0');

            /* blockwise encryption */
            for (int i = 0; i < plain.Length; i += 32)
            {
                if (StringToHex(plain.Substring(i, 32)) == null || StringToHex(tbx_key.Text) == null)
                {
                    MessageBox.Show("Invalid hex value!");
                    return;
                }
                tbx_cipher.Text += HexToString(serpent.Encrypt(StringToHex(plain.Substring(i, 32)), StringToHex(tbx_key.Text)));
            }
            tbx_plain.Text = "";
        }

        /* ------------ STARTING DECRYPTION ------------ */

        private void btn_decrypt_Click(object sender, RoutedEventArgs e)
        {
            if ((tbx_key.Text.Length * 4 != 128) && (tbx_key.Text.Length * 4 != 192) && (tbx_key.Text.Length * 4 != 256))
            {
                MessageBox.Show("Wrong keysize!");
                return;
            }

            serpent = new CSerpent();

            tbx_plain.Text = "";
            /* adding a 0, if the string is not dividable by 32 */
            string cipher = tbx_cipher.Text.Length % 32 == 0 ? tbx_cipher.Text : tbx_cipher.Text.PadRight((tbx_cipher.Text.Length / 32 + 1) * 32, '0');

            /* blockwise decryption */
            for (int i = 0; i < cipher.Length; i = i + 32)
            {
                if (StringToHex(cipher.Substring(i, 32)) == null || StringToHex(tbx_key.Text) == null)
                {
                    MessageBox.Show("Invalid hex value!");
                    return;
                }
                tbx_plain.Text += HexToString(serpent.Decrypt(StringToHex(cipher.Substring(i, 32)), StringToHex(tbx_key.Text)));
            }

            tbx_cipher.Text = "";
        }

        /* converts a string to hexvalues which are written to a uint[] */
        private uint[] StringToHex(string value)
        {
            uint[] num = new uint[value.Length / 8];
            int num1 = 0;
            while (true)
            {
                if ((num1 >= num.Length ? true : value.Length < 8))
                    break;
                try
                {
                    num[num1] = Convert.ToUInt32(value.Substring(0, Math.Min(value.Length, 8)).PadRight(8, '0'), 16);
                }
                catch
                {
                    return null;
                }
                value = value.Substring(8);
                num1++;
            }
            return num;
        }

        /* convert hexvalues (uint[]) to a string */
        private string HexToString(uint[] value)
        {
            string str = "";
            uint[] numArray = value;
            for (int i = 0; i < numArray.Length; i++)
            {
                uint num = numArray[i];
                str = string.Concat(str, num.ToString("X").PadLeft(8, '0'));
            }
            return str;
        }

        /* function which returns the keysize every 250ms */
        private void KeyLength()
        {
            int klength;
            while (true)
            {
                Dispatcher.Invoke((Action)delegate
                {
                    klength = tbx_key.Text.Length * 4;
                    if (klength == 128)
                        lbl_key_length.Foreground = Brushes.Green;
                    else if (klength == 192)
                        lbl_key_length.Foreground = Brushes.Green;
                    else if (klength == 256)
                        lbl_key_length.Foreground = Brushes.Green;
                    else
                        lbl_key_length.Foreground = Brushes.Red;
                    lbl_key_length.Content = klength + " Bits";
                });
                Thread.Sleep(250);
            }
        }
    }
}
