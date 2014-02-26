using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using WORD = System.UInt32;

namespace Serpent
{
    class CSerpent
    {
        public CSerpent()
		{
		    
		}

        private WORD[] roundKeys;
        const uint GOLDEN_RATIO = 0x9e3779b9;

        /* ------------ FUNCTIONS FOR ENCRYPTION ------------ */

        public WORD[] Encrypt(WORD[] input, WORD[] key)
        {
            /* Keyscheduling */

            WORD[] words;
            /* Der Schlüssel wird, wenn er kürzer als 256 Bit lang ist, auf 256Bit aufgefüllt */
            if (key.Length < 8)
            {
                /* dies geschieht durch Anhängen einer 1 und der Rest wird mit 0 aufgefüllt */
                words = new WORD[8];
                Array.Copy(key, words, key.Length);
                words[key.Length] = 1;
                key = words;
            }
            else
            {
                words = new WORD[8];
                Array.Copy(key, words, 8);
                key = words;
            }            

            /* die 8 32-Bit Wörter werden zu 132 32-Bit Prekeys expandiert */
            WORD[] prekeys = new WORD[140];
            Array.Copy(key, prekeys, 8);            
            for (WORD i = 8; i < prekeys.Length; i++)
            {
                /* mit dieser Formel wird der Gesamtschlüssel gleichmäßig über die Rundenschlüssel verteilt */
                prekeys[i] = Rotate(prekeys[i - 8] ^ prekeys[i - 5] ^ prekeys[i - 3] ^ prekeys[i - 1] ^ GOLDEN_RATIO ^ i - 8, -11);
                int num = (int)prekeys[i];
            }
            /* jetzt wird noch die Initial Permutation angewandt und die Schlüssel sind fertig */
            WORD[] tmp = new WORD[4];
            for (int j = 0; j < 33; j++)
            {
                Array.Copy(prekeys, 8 + j * 4, tmp, 0, 4);
                Substitution(tmp, 35 - j, subbox);
                Array.Copy(tmp, 0, prekeys, 8 + j * 4, 4);
            }
            roundKeys = new WORD[132];
            Array.Copy(prekeys, 8, roundKeys, 0, 132);

            /* Encryption*/

            WORD[] cipher = new WORD[] { input[0], input[1], input[2], input[3] };
            /* Insgesamt 32, wovon 31 in ihren Operationen gleich ablaufen */
            for (int i = 0; i < 31; i++)
            {
                AddRoundKey(cipher, i);
                Substitution(cipher, i, subbox);
                EncryptTransformation(cipher);
            }
            /* 32. Runde: hier wird keine Transformation angewandt, sondern mit dem 33. Schlüssel XOR-verknüpft */ 
            AddRoundKey(cipher, 31);
            Substitution(cipher, 31, subbox);
            AddRoundKey(cipher, 32);
            return cipher;
        }

        private void EncryptTransformation(WORD[] input)
        {
            /* Operationen, die in jeder Runde angewandt werden müssen */

            input[0] = Rotate(input[0], -13);
            input[2] = Rotate(input[2], -3);
            input[1] = input[1] ^ input[0] ^ input[2];
            input[3] = input[3] ^ input[2] ^ input[0] << 3;
            input[1] = Rotate(input[1], -1);
            input[3] = Rotate(input[3], -7);
            input[0] = input[0] ^ input[1] ^ input[3];
            input[2] = input[2] ^ input[3] ^ input[1] << 7;
            input[0] = Rotate(input[0], -5);
            input[2] = Rotate(input[2], -22);
        }

        /* ------------ FUNKTIONEN DER ENTSCHLÜSSELUNG ------------ */

        public WORD[] Decrypt(WORD[] input, WORD[] key)
        {
            /* Keyscheduling */

            WORD[] words;
            /* Der Schlüssel wird, wenn er kürzer als 256 Bit lang ist, auf 256Bit aufgefüllt */
            if (key.Length < 8)
            {
                /* dies geschieht durch Anhängen einer 1 und der Rest wird mit 0 aufgefüllt */
                words = new WORD[8];
                Array.Copy(key, words, key.Length);
                words[key.Length] = 1;
                key = words;
            }
            else
            {
                words = new WORD[8];
                Array.Copy(key, words, 8);
                key = words;
            }

            /* die 8 32-Bit Wörter werden zu 132 32-Bit Prekeys expandiert */
            WORD[] prekeys = new WORD[140];
            Array.Copy(key, prekeys, 8);
            for (WORD i = 8; i < prekeys.Length; i++)
            {
                /* mit dieser Formel wird der Gesamtschlüssel gleichmäßig über die Rundenschlüssel verteilt */
                prekeys[i] = Rotate(prekeys[i - 8] ^ prekeys[i - 5] ^ prekeys[i - 3] ^ prekeys[i - 1] ^ GOLDEN_RATIO ^ i - 8, -11);
                int num = (int)prekeys[i];
            }
            /* jetzt wird noch die Initial Permutation angewandt und die Schlüssel sind fertig */
            WORD[] tmp = new WORD[4];
            for (int j = 0; j < 33; j++)
            {
                Array.Copy(prekeys, 8 + j * 4, tmp, 0, 4);
                Substitution(tmp, 35 - j, subbox);
                Array.Copy(tmp, 0, prekeys, 8 + j * 4, 4);
            }
            roundKeys = new WORD[132];
            Array.Copy(prekeys, 8, roundKeys, 0, 132);

            /* Decryption */

            WORD[] plain = new WORD[] { input[0], input[1], input[2], input[3] };
            /* die 32. Runde von der Verschlüsselung ist hier die erste, da alles rückwärts gerechnet wird */
            AddRoundKey(plain, 32);
            Substitution(plain, 31, invsubbox);
            AddRoundKey(plain, 31);
   
            for (int i = 30; i > -1; i--)
            {
                DecryptTransformation(plain);
                Substitution(plain, i, invsubbox);
                AddRoundKey(plain, i);
            }
            return plain;
        }

        private void DecryptTransformation(WORD[] input)
        {
            /* auch beim Entschlüsselen müssen wieder Operationen angewandt werden, nur diesmal in die andere Richtung */

            input[2] = Rotate(input[2], 22);
            input[0] = Rotate(input[0], 5);
            input[2] = input[2] ^ input[3] ^ input[1] << 7;
            input[0] = input[0] ^ input[1] ^ input[3];
            input[3] = Rotate(input[3], 7);
            input[1] = Rotate(input[1], 1);
            input[3] = input[3] ^ input[2] ^ input[0] << 3;
            input[1] = input[1] ^ input[0] ^ input[2];
            input[2] = Rotate(input[2], 3);
            input[0] = Rotate(input[0], 13);
        }

        /* ------------ OPERATIONEN FÜR BEIDE ------------ */

		private WORD Rotate(WORD value, int positions)
		{
            return Convert.ToUInt32(((value << positions) | (value >> (32 - positions))) & 0xffffffff);
		}

		private void Substitution(WORD[] input, int round, byte[][] substitution)
		{
            /* hier werden die Substitutionsboxen angewandt (je nach Richtung die normale oder die inverse Box (siehe unten) */
	        byte[] tmp = substitution[round % 8];
            /* Erzeugen eines Nibbles */
			WORD num0 = input[0];
			WORD num1 = input[1];
			WORD num2 = input[2];
			WORD num3 = input[3];
			WORD num4 = 0;
			WORD num5 = 0;
			WORD num6 = 0;
			WORD num7 = 0;
            /* Operationen für die Substitution */
			for (int i = 0; i < 32; i++)
			{
				WORD num8 = tmp[num0 >> (i & 31) & 1 | (num1 >> (i & 31) & 1) << 1 | (num2 >> (i & 31) & 1) << 2 | (num3 >> (i & 31) & 1) << 3];
				num4 = num4 | (num8 & 1) << (i & 31);
				num5 = num5 | (num8 >> 1 & 1) << (i & 31);
				num6 = num6 | (num8 >> 2 & 1) << (i & 31);
				num7 = num7 | (num8 >> 3 & 1) << (i & 31);
			}

			input[0] = num4;
			input[1] = num5;
			input[2] = num6;
			input[3] = num7;
		}        

        /* XOR-Verknüpfung vom Block und dem Rundenschlüssel (wird in jeder Runde gemacht) */
        private void AddRoundKey(WORD[] input, int round)
        {
            for (int i = 0; i < 4; i++)
                input[i] = input[i] ^ roundKeys[round * 4 + i];
        }

        /* ------------ SUBSTITUTIONSBOXEN ------------ */

        /* Substitutionsbox zum Verschlüsseln */
        public static byte[][] subbox = new byte[][] 
        { 
            new byte[] { 3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12 }, 
            new byte[] { 15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4 }, 
            new byte[] { 8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2 }, 
            new byte[] { 0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14 }, 
            new byte[] { 1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13 }, 
            new byte[] { 15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1 }, 
            new byte[] { 7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0 }, 
            new byte[] { 1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6 } 
        };

        /* Substitutionsbox zum Entschlüsseln */
        public static byte[][] invsubbox =
        {
            new byte[] { 13, 3, 11, 0, 10, 6, 5, 12, 1, 14, 4, 7, 15, 9, 8, 2 }, 
            new byte[] { 5, 8, 2, 14, 15, 6, 12, 3, 11, 4, 7, 9, 1, 13, 10, 0 }, 
            new byte[] { 12, 9, 15, 4, 11, 14, 1, 2, 0, 3, 6, 13, 5, 8, 10, 7 }, 
            new byte[] { 0, 9, 10, 7, 11, 14, 6, 13, 3, 5, 12, 2, 4, 8, 15, 1 }, 
            new byte[] { 5, 0, 8, 3, 10, 9, 7, 14, 2, 12, 11, 6, 4, 15, 13, 1 }, 
            new byte[] { 8, 15, 2, 9, 4, 1, 13, 14, 11, 6, 5, 3, 7, 12, 10, 0 }, 
            new byte[] { 15, 10, 1, 13, 5, 3, 6, 0, 4, 9, 14, 7, 2, 12, 8, 11 }, 
            new byte[] { 3, 0, 6, 13, 9, 14, 15, 8, 5, 12, 11, 7, 10, 1, 4, 2 }
        };
    }
}
