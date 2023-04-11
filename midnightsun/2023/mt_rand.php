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