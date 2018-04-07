<?php

namespace Lefuturiste\LessPass;

/**
 * Less pass generator class
 *
 * Original idea : http://lesspass.com/
 * Algorithm based on : https://github.com/mevdschee/lesspass.php
 * Additional tests : https://github.com/mevdschee/lesspass.php/tree/master/tests
 * Requirements : > PHP 5.5 && GNU Multiple Precision (php-gmp)
 */
class LessPassGenerator
{

	/**
	 * @var array
	 **/
	public $passwordProfile;

	public $defaultPasswordProfile = [
		'lowercase' => true,
		'uppercase' => true,
		'numbers' => true,
		'symbols' => true,
		'digest' => 'sha256',
		'iterations' => 100000,
		'keylen' => 32,
		'length' => 16,
		'counter' => 1,
		'version' => 2
	];

	private $characterSubsets = [
		'lowercase' => 'abcdefghijklmnopqrstuvwxyz',
		'uppercase' => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
		'numbers' => '0123456789',
		'symbols' => '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
	];

	public function __construct(array $passwordProfile = [])
	{
		$this->passwordProfile = $passwordProfile;
	}

	/**
	 * Generate a password from parameters
	 *
	 * @param $site eg: example.com
	 * @param $login eg: myLogin
	 * @param $masterPassword eg: masterPasswordVerySecure
	 * @param null $passwordProfile New array of password profile, to erase the default and the constructor
	 * @return string
	 */
	public function generatePassword($site, $login, $masterPassword, $passwordProfile = NULL)
	{
		if ($passwordProfile = NULL) {
			$passwordProfile = $this->passwordProfile;
		}
		$passwordProfile = $this->getPasswordProfile($passwordProfile);
		$entropy = $this->calcEntropy($site, $login, $masterPassword, $passwordProfile);

		return $this->renderPassword($entropy, $passwordProfile);
	}

	/**
	 * Get the password profile to use between the last, the constructor profile and the default
	 *
	 * @param $passwordProfile
	 * @return object
	 */
	private function getPasswordProfile($passwordProfile)
	{
		$defaultPasswordProfile = (object)$this->defaultPasswordProfile;

		return (object)array_merge((array)$defaultPasswordProfile, (array)$passwordProfile, (array)$this->passwordProfile);
	}

	private function calcEntropy($site, $login, $masterPassword, $passwordProfile)
	{
		$salt = $site . $login . dechex($passwordProfile->counter);

		return hash_pbkdf2($passwordProfile->digest, $masterPassword, $salt, $passwordProfile->iterations, $passwordProfile->keylen * 2);
	}

	private function renderPassword($entropy, $passwordProfile)
	{
		$rules = $this->getConfiguredRules($passwordProfile);
		$setOfCharacters = $this->getSetOfCharacters($rules);
		list($password, $passwordEntropy) = $this->consumeEntropy('', gmp_init($entropy, 16), $setOfCharacters, $passwordProfile->length - count($rules));
		list($charactersToAdd, $characterEntropy) = $this->getOneCharPerRule($passwordEntropy, $rules);

		return $this->insertStringPseudoRandomly($password, $characterEntropy, $charactersToAdd);
	}


	private function getSetOfCharacters($rules = NULL)
	{
		$characterSubsets = (object)$this->characterSubsets;
		if (!$rules) {
			return $characterSubsets->lowercase . $characterSubsets->uppercase . $characterSubsets->numbers . $characterSubsets->symbols;
		}
		$setOfChars = '';
		foreach ($rules as $rule) {
			$setOfChars .= $characterSubsets->$rule;
		}

		return $setOfChars;
	}

	private function consumeEntropy($generatedPassword, $quotient, $setOfCharacters, $maxLength)
	{
		if (strlen($generatedPassword) >= $maxLength) {
			return [$generatedPassword, $quotient];
		}
		list($quotient, $remainder) = gmp_div_qr($quotient, strlen($setOfCharacters));
		$generatedPassword .= $setOfCharacters[(int)$remainder];

		return $this->consumeEntropy($generatedPassword, $quotient, $setOfCharacters, $maxLength);
	}

	private function insertStringPseudoRandomly($generatedPassword, $entropy, $string)
	{
		for ($i = 0; $i < strlen($string); $i++) {
			list($quotient, $remainder) = gmp_div_qr($entropy, strlen($generatedPassword));
			$generatedPassword = substr($generatedPassword, 0, (int)$remainder) . $string[$i] . substr($generatedPassword, (int)$remainder);
			$entropy = $quotient;
		}

		return $generatedPassword;
	}

	private function getOneCharPerRule($entropy, $rules)
	{
		$characterSubsets = (object)$this->characterSubsets;
		$oneCharPerRules = '';
		foreach ($rules as $rule) {
			list($value, $entropy) = $this->consumeEntropy('', $entropy, $characterSubsets->$rule, 1);
			$oneCharPerRules .= $value;
		}

		return [$oneCharPerRules, $entropy];
	}

	private function getConfiguredRules($passwordProfile)
	{
		return array_merge(array_filter(['lowercase', 'uppercase', 'numbers', 'symbols'], function ($rule) use ($passwordProfile) {
			return isset($passwordProfile->$rule) && $passwordProfile->$rule;
		}));
	}

}
