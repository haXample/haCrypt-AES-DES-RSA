## haCrypt Test-Menu Usage

Sample#1 (AsciiHex)  

```
KEY1 = 627f460e08104a10 
KEY2 = 43cd265d5840eaf1
KEY3 = 313edf97df2a8a8c
IV = 8e29f75ea77e5475
PLAINTEXT =  326a494cd33fe756
CIPHERTEXT = b22b8d66de970692
```

Sample#2 (AsciiHex)  

```
KEY1 = 37ae5ebf46dff2dc          
KEY2 = 0754b94f31cbb385
KEY3 = 5e7fd36dc870bfae
IV = 3d1de3cc132e3b65
PLAINTEXT =  84401f78fe6c1087 6d8ea23094ea5309
CIPHERTEXT = 7b1f7c7e3b1c948e bd04a75ffba7d2f5
```

#### Using haCrypt Test-Menu to easily veriify the Sample#1

1) start haCrypt and in Crypto-Menu choose choose `[3DES]-[TDES /ENCRYPT (CBC Ciphertext stealing]`  
2) select `[/TEXT editor mode]`	and copy *KEY1..Key3* into the text field  
3) right-click the toolbar and select `[Test]-[AscHex2Bin edited text]`   
4) define the key in the dialog by clicking the [KEY] button   
KEY1 = 627f460e08104a10            
KEY2 = 43cd265d5840eaf1  
KEY3 = 313edf97df2a8a8c  
[screenshot](image/TestMenu01.jpg)  

5) select `[/TEXT editor mode]`	and copy *IV* into the text field  
6) right-click the toolbar and select `[Test]-[AscHex2Bin edited text]`   
7) define the Initial Chaining Vector clicking the [IV] button   
IV = 8e29f75ea77e5475  
[screenshot](image/TestMenu02.jpg)  
	
8) select `[/TEXT editor mode]`	and copy *PLAINTEXT* into the text field     
9) right-click the toolbar and select `[Test]-[AscHex2Bin edited text]`   
10) apply the crpto algorithm clicking the [Plaintext] button   
PLAINTEXT =  326a494cd33fe756   

11) verify the result in the text field conforms the initial condition  
**CIPHERTEXT = B2 2B 8D 66 DE 97 06 92**  
[screenshot](image/TestMenu03.jpg)  

#### haCrypt Test-Menu result for Sample#2

CIPHERTEXT = 7B 1F 7C 7E 3B 1C 94 8E BD 04 A7 5F FB A7 D2 F5  
