   M S B A M L   `   `   `  ����  Serpent    Serpent.MainWindow   5   	   \ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5   	   R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   -   5          � Title$  
MainWindow��5   	   $	��364��6   $	��530��6)   .��5      � .+�5   
   �� $��Plaintext in hexformat :��6   $
��Left=�63   $��	10,10,0,0q�6N   $	��Top=�6a   �� 5   
   -   5         ��Name$ 	tbx_plain��5      $
��Left=�6%   $��23��6@   $��	10,36,0,0q�6L    �� TextWrapping$
 Wrap=�6_   $	��Top=�6s   $	��485��6�   �� 5   
   $��Key in hexformat :��6   $
��Left=�6-   $��
10,123,0,0q�6H   $	��Top=�6\   �� 5	   
   -   5        $ tbx_key��5	      $
��Left=�6#   $��23��6>   $��
10,154,0,0q�6J   $
 Wrap=�6^   $	��Top=�6r   $	��485��6�   �� 5
   
   -   5         ��Name$ btn_encrypt��5
      $��Encrypt��6&   $
��Left=�68   $��120,261,0,0q�6S   $	��Top=�6h   $	��122��6�   $��34��6�   6�   �� 5   
   $?��9Warning: only key sizes 128, 192 and 256 bits are allowed��6   $
��Left=�6T   $��
10,182,0,0q�6o   $	��Top=�6�   �� 5   
   $��Current keysize :��6   $
��Left=�6,   $��
10,213,0,0q�6G   $	��Top=�6[   �� 5   
   -   5         ��Name$ lbl_key_length��5      $�� ��6(   $
��Left=�63   $��112,213,0,0q�6N   $	��Top=�6c   ���	#FFFF0C00 J� RenderTransformOrigin$ 
0.4,-2.154&�6�   �� 5   
   $��Ciphertext in hexformat :��6   $
��Left=�64   $��	10,64,0,0q�6O   $	��Top=�6b   �� 5   
   -   5        $ 
tbx_cipher��5      $
��Left=�6&   $��23��6A   $��	10,95,0,0q�6M   $
 Wrap=�6`   $	��Top=�6t   $	��485��6�   �� 5   
   -   5        $ btn_decrypt��5      $��Decrypt��6&   $
��Left=�68   $��289,261,0,0q�6S   $	��Top=�6h   $	��122��6�   $��34��6�   6�   5      5      