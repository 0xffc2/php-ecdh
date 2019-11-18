<?php

function str2hex($hex, $with='\\x') {
	$hex = strval($hex);
	$len = strlen($hex);
	$str = '';
	for ($i=0; $i < $len; $i++) {
		$tmp = strtoupper(dechex(ord($hex[$i])));
		if (strlen($tmp) == 1) {
			$tmp = '0'.$tmp;
		}
		$str .= $with.$tmp;
	}
	return $str;
}

function toBin($data)
{
	return hex2bin(preg_replace('/\s/', '', $data));
}

function toHex($data, $with='')
{
	return trim(str2hex($data, $with));
}

$srvpub = toBin('02928d8850673088b343264e0c6bacb8496d697799f37211de');
if ($ret = ecdh_generate_key($srvpub)) {
	foreach ($ret as $key => $value) {
		echo "$key : " .strlen($value) .' : '. toHex($value) . "\n";
	}
}

// shareKey = 'BA1B5A84E7C0D25D11784CAE74C83F50';
$prikey = toBin('0000001900bd3d651f6a401b6f6dc6acbcb4b901e1bbc652b3813fdee7');
$srvpub = toBin('032c75720428314687959a18383aeff60ad3a6da17423ee32b');
if ($ret = ecdh_compute_key($prikey, $srvpub)) {
	foreach ($ret as $key => $value) {
		echo "$key : " .strlen($value) .' : '. toHex($value) . "\n";
	}
}
