<?php

class GeneratorTest extends \PHPUnit\Framework\TestCase
{

	public function testNormal()
	{
		$generator = new \Lefuturiste\LessPass\LessPassGenerator();
		$result = $generator->generatePassword('example.com', 'myLogin', 'masterPasswordVerySecure');
		$this->assertEquals($result, "UnwbW6</]|<?MVgM");
		$this->assertEquals(16, strlen($result));
	}

	public function testLength()
	{
		$generator = new \Lefuturiste\LessPass\LessPassGenerator([
			'length' => 20
		]);
		$result = $generator->generatePassword('example.com', 'myLogin', 'masterPasswordVerySecure');
		$this->assertEquals($result, "UnwMb<_]8|<?MVMx])a)");
		$this->assertEquals(20, strlen($result));
	}
}